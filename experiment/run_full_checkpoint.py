# -*- coding: utf-8 -*-
"""
run_full_checkpoint.py -- 全量/扩样本 官方任务 真实 LLM 评测 (可断点续跑)

设计要点:
  - 逐任务评测, 每完成一条立即追加写 checkpoint CSV (断点续跑, 杀掉不丢)
  - --all        跑全部 1100 条
  - --per N       按 (attack x domain) 每格取 N 条 (用于 n>=N/类 扩样本)
  - --budget S    最多跑 S 秒后主动退出 (配合多轮前台调用拼满)
  - --adaptive    额外跑自适应攻击者评估 (任一次扰动突破即 baseline_adapt=1)
  - --delay D     每次 LLM 调用间隔 (秒), 防限流
  - 复用 a2asecbench_adapter 的 run_baseline / run_pqaib / run_adaptive_baseline

注意: run_pqaib 是确定性网关判定 (不调 LLM), 仅 baseline/adaptive 走真实端点。

用法:
  python run_full_checkpoint.py --model sensenova-6.8-flash-lite --all --budget 540
  python run_full_checkpoint.py --model sensenova-6.8-flash-lite --per 20 --no-adaptive
  (后台全量)  python run_full_checkpoint.py --model sensenova-6.8-flash-lite --all --delay 0 --checkpoint results/full_sensenova.csv &
"""
import argparse, csv, json, os, sys, time
import a2asecbench_adapter as A


def task_id(t, idx):
    return t.get("id") or t.get("case_id") or f"{t.get('attack')}_{t.get('domain')}_{idx}"


def sample_per_cell(tasks, per):
    from collections import defaultdict
    groups = defaultdict(list)
    for i, t in enumerate(tasks):
        key = (t.get("attack") or "benign", t.get("domain"))
        groups[key].append((i, t))
    out = []
    for key, items in groups.items():
        n = min(per, len(items))
        out.extend([t for _, t in items[:n]])
    return out


def load_checkpoint(path):
    done = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                done[row["task_id"]] = True
    return done


def run_one(t, llm, bir, honest, adaptive, delay):
    t0 = time.time()
    base_tool = A.run_baseline(t, llm)
    pq = A.run_pqaib(t, llm, bir, honest)
    base_success = (base_tool == t.get("target_capability"))
    pq_success = (pq == "allow")  # allow = PQ-AIB 失败
    base_adapt = ""
    if adaptive and t["kind"] == "adversarial":
        base_adapt = "1" if A.run_adaptive_baseline(t, llm) else "0"
    if delay:
        time.sleep(delay)
    return {
        "base_tool": base_tool or "",
        "base_success": int(base_success),
        "pq_decision": pq or "",
        "pq_success": int(pq_success),
        "base_adapt_success": base_adapt,
        "latency_s": round(time.time() - t0, 3),
    }


def aggregate(rows):
    from collections import defaultdict
    agg = {"baseline": defaultdict(lambda: [0, 0]),
           "pqaib": defaultdict(lambda: [0, 0]),
           "baseline_adapt": defaultdict(lambda: [0, 0])}
    for r in rows:
        atk = r["attack"]
        agg["baseline"][atk][1] += 1
        agg["baseline"][atk][0] += int(r["base_success"])
        agg["pqaib"][atk][1] += 1
        agg["pqaib"][atk][0] += int(r["pq_success"])
        if r["base_adapt_success"] != "":
            agg["baseline_adapt"][atk][1] += 1
            agg["baseline_adapt"][atk][0] += int(r["base_adapt_success"])
    return agg


def write_aggregate(agg, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("defense,attack,success,total,asr\n")
        for defense in ["baseline", "pqaib", "baseline_adapt"]:
            for atk, (s, tot) in sorted(agg[defense].items()):
                rate = s / tot if tot else 0.0
                f.write(f"{defense},{atk},{s},{tot},{rate:.4f}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="sensenova-6.8-flash-lite")
    ap.add_argument("--data", default="../a2asecbench_tasks.json")
    ap.add_argument("--all", action="store_true", help="跑全部任务")
    ap.add_argument("--per", type=int, default=0, help="每 (attack x domain) 格取样数")
    ap.add_argument("--domain", choices=A.DOMAINS + ["all"], default="all")
    ap.add_argument("--shard", type=int, default=0, help="分片序号 (0-based)")
    ap.add_argument("--nshards", type=int, default=1, help="总分片数 (跨端点并行)")
    ap.add_argument("--adaptive", action="store_true")
    ap.add_argument("--no-adaptive", dest="adaptive", action="store_false")
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--budget", type=float, default=0.0, help="最多跑多少秒")
    ap.add_argument("--out", default="results")
    ap.add_argument("--checkpoint", default="")
    ap.add_argument("--resume-from", default="",
                    help="合并已有 checkpoint 的 task_id 作为全局跳过集 (跨分片续跑)")
    args = ap.parse_args()

    # 加载官方任务
    with open(args.data, encoding="utf-8") as f:
        all_tasks = json.load(f)
    if args.domain != "all":
        all_tasks = [t for t in all_tasks if t.get("domain") == args.domain]

    # 取样
    if args.all:
        tasks = all_tasks
        tag = "all"
    elif args.per > 0:
        tasks = sample_per_cell(all_tasks, args.per)
        tag = f"per{args.per}"
    else:
        tasks = all_tasks
        tag = "all"

    # 分片 (跨端点并行)
    if args.nshards > 1:
        tasks = [t for i, t in enumerate(tasks) if i % args.nshards == args.shard]
        tag = f"shard{args.shard}of{args.nshards}"

    ckpt = args.checkpoint or os.path.join(args.out, f"full_{args.model}_{tag}.csv")
    os.makedirs(args.out, exist_ok=True)
    done = load_checkpoint(ckpt)
    if args.resume_from and os.path.exists(args.resume_from):
        ext = load_checkpoint(args.resume_from)
        if ext:
            done.update(ext)
            print(f"[*] --resume-from {args.resume_from}: 合并 {len(ext)} 条已完成 task_id")

    models = A.load_models("models.txt")
    if args.model not in models:
        print(f"[ERR] models.txt 无 {args.model}"); sys.exit(1)
    llm = A.LLMClient(args.model, models, mock=False)
    bir = A.BIR()
    honest = A.Agent("honest-agent", ["book_flight", "schedule_appointment", "query_balance"],
                     {"max_priv": 1}, bir)

    # 追加写 checkpoint
    write_header = not os.path.exists(ckpt)
    cf = open(ckpt, "a", encoding="utf-8", newline="")
    cw = csv.writer(cf)
    if write_header:
        cw.writerow(["task_id", "attack", "domain", "kind", "target_capability",
                     "base_tool", "base_success", "pq_decision", "pq_success",
                     "base_adapt_success", "latency_s"])
        cf.flush()

    remaining = [t for i, t in enumerate(tasks) if task_id(t, i) not in done]
    print(f"[*] 总任务 {len(tasks)}, 已完成 {len(tasks)-len(remaining)}, 待跑 {len(remaining)}")
    print(f"[*] checkpoint={ckpt}, model={args.model}, adaptive={args.adaptive}, delay={args.delay}, budget={args.budget}s")

    t0 = time.time()
    processed = 0
    for i, t in enumerate(tasks):
        tid = task_id(t, i)
        if tid in done:
            continue
        try:
            res = run_one(t, llm, bir, honest, args.adaptive, args.delay)
        except Exception as e:
            print(f"[WARN] 任务 {tid} 失败: {e}")
            if args.delay:
                time.sleep(args.delay)
            continue
        cw.writerow([tid, t.get("attack"), t.get("domain"), t.get("kind"),
                     t.get("target_capability"), res["base_tool"], res["base_success"],
                     res["pq_decision"], res["pq_success"], res["base_adapt_success"],
                     res["latency_s"]])
        cf.flush()
        processed += 1
        done[tid] = True
        if args.budget and (time.time() - t0) >= args.budget:
            print(f"[*] 预算 {args.budget}s 到, 退出 (本轮处理 {processed} 条)")
            break

    cf.close()
    elapsed = time.time() - t0

    # 读取全部 checkpoint 行做聚合
    all_rows = []
    with open(ckpt, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            all_rows.append(row)
    agg = aggregate(all_rows)
    agg_path = os.path.join(args.out, f"full_{args.model}_{tag}_aggregate.csv")
    write_aggregate(agg, agg_path)

    print(f"\n=== 聚合 ({len(all_rows)} 条, model={args.model}) ===")
    print(f"{'attack':<16}{'baseline_ASR':>14}{'pqaib_ASR':>12}{'base_adapt':>12}")
    for atk in A.ATTACKS:
        b = agg["baseline"][atk]; p = agg["pqaib"][atk]; a = agg["baseline_adapt"][atk]
        ba = b[0]/b[1] if b[1] else 0
        pa = p[0]/p[1] if p[1] else 0
        aa = a[0]/a[1] if a[1] else 0
        print(f"{atk:<16}{ba:>14.3f}{pa:>12.3f}{aa:>12.3f}")
    bn = agg["pqaib"].get("benign", [0, 0])
    print(f"{'benign_FNR':<16}{'-':>14}{bn[0]/bn[1] if bn[1] else 0:>12.3f}")
    print(f"本轮处理 {processed} 条, 累计 checkpoint {len(all_rows)} 条, 耗时 {elapsed:.1f}s")
    print(f"聚合 -> {agg_path}")


if __name__ == "__main__":
    main()
