# -*- coding: utf-8 -*-
"""
run_official_subset.py -- 从官方 1100 条任务中取样 + 真实 LLM 评测

解决"全量 1100 条真实跑超出沙箱单回合时长"的问题：
  1. 从 a2asecbench_tasks.json 按 attack × domain 分层取样（每类 N 条）
  2. 写出子集 JSON
  3. 调用 a2asecbench_adapter 主流程做真实 LLM 评测（baseline + PQ-AIB 双轨）

用法:
  python run_official_subset.py --model sensenova-6.8-flash-lite --per 3 --domain all
  python run_official_subset.py --model dots3-note-prev --per 2 --domain travel --adaptive

输出: results/a2asecbench_official_<model>_<domain>_n<per>.csv
"""
import argparse, json, os, sys, time
import a2asecbench_adapter as A


def sample_tasks(tasks, per, domain):
    """按 attack × domain 分层取样，每类 per 条。"""
    from collections import defaultdict
    groups = defaultdict(list)
    for t in tasks:
        if domain != "all" and t.get("domain") != domain:
            continue
        atk = t.get("attack") or "benign"
        groups[atk].append(t)

    sampled = []
    for atk, items in groups.items():
        # 优先取非 control 的（攻击任务），control 良性任务按需
        non_control = [t for t in items if not t.get("is_control", False)]
        pool = non_control if non_control else items
        n = min(per, len(pool))
        sampled.extend(pool[:n])

    return sampled


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="sensenova-6.8-flash-lite")
    ap.add_argument("--domain", choices=A.DOMAINS + ["all"], default="all")
    ap.add_argument("--per", type=int, default=3, help="每类样本数")
    ap.add_argument("--data", default="a2asecbench_tasks.json")
    ap.add_argument("--adaptive", action="store_true")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--out", default="results")
    ap.add_argument("--dry-run", action="store_true", help="仅取样不跑 LLM")
    args = ap.parse_args()

    # 1. 加载官方任务
    with open(args.data, encoding="utf-8") as f:
        all_tasks = json.load(f)
    print(f"[1/4] 加载官方任务: {len(all_tasks)} 条")

    # 2. 取样
    sampled = sample_tasks(all_tasks, args.per, args.domain)
    print(f"[2/4] 取样: {len(sampled)} 条 (per={args.per}, domain={args.domain})")
    # 打印分布
    from collections import Counter
    dist = Counter((t.get("attack"), t.get("domain")) for t in sampled)
    for (atk, dom), cnt in sorted(dist.items()):
        print(f"  {atk:<16} {dom:<12} {cnt}")

    if args.dry_run:
        print("[dry-run] 退出")
        return

    # 3. 写出子集
    os.makedirs(args.out, exist_ok=True)
    sub_path = os.path.join(args.out, "a2asecbench_official_subset.json")
    with open(sub_path, "w", encoding="utf-8") as f:
        json.dump(sampled, f, ensure_ascii=False, indent=1)
    print(f"[3/4] 子集 -> {sub_path} ({len(sampled)} 条)")

    # 4. 真实 LLM 评测（复用 adapter 主流程）
    print(f"[4/4] 启动真实 LLM 评测 (model={args.model})...")
    t0 = time.time()

    # 直接调用 adapter 的核心函数
    models = A.load_models("models.txt")
    if args.model not in models:
        print(f"[ERR] models.txt 无 {args.model}"); sys.exit(1)
    llm = A.LLMClient(args.model, models, mock=False)
    bir = A.BIR()
    honest = A.Agent("honest-agent", ["book_flight", "schedule_appointment", "query_balance"],
                     {"max_priv": 1}, bir)

    rows = A.evaluate(sampled, llm, bir, honest, delay=args.delay)
    elapsed = time.time() - t0

    # 写出 CSV
    tag = f"official_{args.model}_{args.domain}_n{args.per}"
    csv_path = os.path.join(args.out, f"a2asecbench_{tag}.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("defense,attack,success,total,asr_or_fnr,latency_ms_per_task\n")
        n_tasks = len(sampled)
        for defense in ["baseline", "pqaib"]:
            for atk, (succ, tot) in rows[defense].items():
                rate = (succ / tot) if tot else 0.0
                f.write(f"{defense},{atk},{succ},{tot},{rate:.4f},{1000*elapsed/n_tasks:.2f}\n")

    # 摘要
    print(f"\n=== 官方任务真实 LLM 评测摘要 ({args.domain}, model={args.model}, n={len(sampled)}) ===")
    print(f"{'attack':<16}{'baseline_ASR':>14}{'pqaib_ASR':>12}")
    for atk in A.ATTACKS:
        b = rows["baseline"].get(atk, (0, 0)); p = rows["pqaib"].get(atk, (0, 0))
        ba = b[0]/b[1] if b[1] else 0; pa = p[0]/p[1] if p[1] else 0
        print(f"{atk:<16}{ba:>14.3f}{pa:>12.3f}")
    bn = rows["pqaib"].get("benign", (0, 0))
    print(f"{'benign_FNR':<16}{'-':>14}{bn[0]/bn[1] if bn[1] else 0:>12.3f}")
    print(f"耗时 {elapsed:.1f}s, 任务 {n_tasks}, 结果 -> {csv_path}")

    # 自适应
    if args.adaptive:
        print(f"\n--- 自适应攻击者评估 ---")
        t1 = time.time()
        adapt = A.evaluate_adaptive(sampled, llm, bir, honest, delay=args.delay)
        a_csv = os.path.join(args.out, f"a2asecbench_{tag}_adapt.csv")
        with open(a_csv, "w", encoding="utf-8") as f:
            f.write("defense,attack,success,total,asr_adapt\n")
            for defense in ["baseline", "pqaib"]:
                for atk, (succ, tot) in adapt[defense].items():
                    f.write(f"{defense},{atk},{succ},{tot},{(succ/tot if tot else 0):.4f}\n")
        print(f"{'attack':<16}{'baseline_adapt':>15}{'pqaib_adapt':>13}")
        for atk in A.ATTACKS:
            b = adapt["baseline"].get(atk, (0, 0)); p = adapt["pqaib"].get(atk, (0, 0))
            ba = b[0]/b[1] if b[1] else 0; pa = p[0]/p[1] if p[1] else 0
            print(f"{atk:<16}{ba:>15.3f}{pa:>13.3f}")
        print(f"自适应结果 -> {a_csv} (耗时 {time.time()-t1:.1f}s)")

    # 画图
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = A.ATTACKS
        basev = [rows["baseline"].get(a, (0, 0))[0]/rows["baseline"].get(a, (0, 0))[1]
                 if rows["baseline"].get(a, (0, 0))[1] else 0 for a in labels]
        pqv = [rows["pqaib"].get(a, (0, 0))[0]/rows["pqaib"].get(a, (0, 0))[1]
               if rows["pqaib"].get(a, (0, 0))[1] else 0 for a in labels]
        x = range(len(labels)); w = 0.38
        fig, ax = plt.subplots(figsize=(9, 4.5))
        ax.bar([i - w/2 for i in x], basev, w, label="Baseline (no defense)", color="#c0392b")
        ax.bar([i + w/2 for i in x], pqv, w, label="PQ-AIB", color="#27ae60")
        ax.set_xticks(list(x)); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
        ax.set_ylabel("ASR"); ax.set_ylim(0, 1.05)
        ax.set_title(f"Official A2ASecBench replay — ASR by attack ({args.domain}, {args.model})")
        ax.legend(); fig.tight_layout()
        png = os.path.join(args.out, f"a2asecbench_{tag}.png")
        fig.savefig(png, dpi=120)
        print(f"图 -> {png}")
    except Exception as e:
        print(f"[WARN] 画图失败: {e}")


if __name__ == "__main__":
    main()