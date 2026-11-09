# -*- coding: utf-8 -*-
"""
catchup_missing.py -- 仅补跑全量分片里"失败/未覆盖"的 task_id (断点续跑收尾)

读取 a2asecbench_tasks.json (全量 1100) 与所有分片 checkpoint, 计算缺失 task_id,
轮询 3 个可达端点逐条补跑, 追加写 results/full_catchup.csv。

用法:
  python catchup_missing.py
  python catchup_missing.py --models dots3-note-prev,sensenova-6.8-flash-lite,Agents-A1
"""
import argparse, csv, json, os, sys, time
import a2asecbench_adapter as A


def task_id(t, idx):
    return t.get("id") or t.get("case_id") or f"{t.get('attack')}_{t.get('domain')}_{idx}"


def load_done(paths):
    done = set()
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("task_id"):
                    done.add(row["task_id"])
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../a2asecbench_tasks.json")
    ap.add_argument("--glob", default="results/full_*.csv")
    ap.add_argument("--models", default="dots3-note-prev,sensenova-6.8-flash-lite,Agents-A1")
    ap.add_argument("--delay", type=float, default=0.2)
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    import glob
    with open(args.data, encoding="utf-8") as f:
        all_tasks = json.load(f)
    id_to_task = {task_id(t, i): t for i, t in enumerate(all_tasks)}

    paths = sorted(glob.glob(args.glob))
    done = load_done(paths)
    missing = [tid for tid in id_to_task if tid not in done]
    print(f"[*] 全量 {len(all_tasks)} 条, 已完成 {len(done)}, 缺失 {len(missing)}")

    if not missing:
        print("[*] 无缺失, 无需补跑")
        return

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    mcfg = A.load_models("models.txt")
    clients = {}
    for m in models:
        if m in mcfg:
            clients[m] = A.LLMClient(m, mcfg, mock=False)
    if not clients:
        print("[ERR] 无可用端点"); sys.exit(1)
    bir = A.BIR()
    honest = A.Agent("honest-agent", ["book_flight", "schedule_appointment", "query_balance"],
                     {"max_priv": 1}, bir)

    ckpt = os.path.join(args.out, "full_catchup.csv")
    os.makedirs(args.out, exist_ok=True)
    write_header = not os.path.exists(ckpt)
    cf = open(ckpt, "a", encoding="utf-8", newline="")
    cw = csv.writer(cf)
    if write_header:
        cw.writerow(["task_id", "attack", "domain", "kind", "target_capability",
                     "base_tool", "base_success", "pq_decision", "pq_success",
                     "base_adapt_success", "latency_s"])
        cf.flush()

    ok = 0
    for i, tid in enumerate(missing):
        t = id_to_task[tid]
        model = models[i % len(models)]
        llm = clients[model]
        try:
            t0 = time.time()
            base_tool = A.run_baseline(t, llm)
            pq = A.run_pqaib(t, llm, bir, honest)
            base_success = int((base_tool == t.get("target_capability")))
            pq_success = int(pq == "allow")
            if args.delay:
                time.sleep(args.delay)
            cw.writerow([tid, t.get("attack"), t.get("domain"), t.get("kind"),
                         t.get("target_capability"), base_tool or "", base_success,
                         pq or "", pq_success, "", round(time.time() - t0, 3)])
            cf.flush()
            ok += 1
        except Exception as e:
            print(f"[WARN] {tid} 失败: {e}")
    cf.close()
    print(f"[*] 补跑完成: 成功 {ok}/{len(missing)} -> {ckpt}")


if __name__ == "__main__":
    main()
