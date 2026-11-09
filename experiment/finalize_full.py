# -*- coding: utf-8 -*-
"""
finalize_full.py -- 全量收尾: 覆盖度检查 + 逐 (attack x domain) 样本量表 + 聚合 + 出图

读取 a2asecbench_tasks.json (全量 1100) 与所有分片 checkpoint (含 catchup), 去重后:
  1) 覆盖度: 已完成 / 1100, 列出缺失 task_id
  2) 逐 (attack x domain) 样本量 n (确认 n>=20)
  3) 逐 attack 聚合 baseline/pqaib ASR + benign FNR
  4) 出图 full_combined_asr.png

用法:
  python finalize_full.py
"""
import argparse, csv, glob, json, os
from collections import defaultdict
import a2asecbench_adapter as A


def task_id(t, idx):
    return t.get("id") or t.get("case_id") or f"{t.get('attack')}_{t.get('domain')}_{idx}"


def load_rows(paths):
    rows = {}
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            r = csv.reader(f)
            h = next(r, None)
            if not h or h[0] != "task_id":
                continue
            for row in r:
                if len(row) < 11:
                    continue
                tid = row[0]
                if tid in rows:
                    continue
                rows[tid] = {"task_id": row[0], "attack": row[1], "domain": row[2],
                             "kind": row[3], "base_success": int(row[6]),
                             "pq_success": int(row[8]), "base_adapt": row[9]}
    return list(rows.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../a2asecbench_tasks.json")
    ap.add_argument("--glob", default="results/full_*.csv")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    with open(args.data, encoding="utf-8") as f:
        all_tasks = json.load(f)
    all_ids = [task_id(t, i) for i, t in enumerate(all_tasks)]

    paths = sorted(glob.glob(args.glob))
    rows = load_rows(paths)
    done_ids = {r["task_id"] for r in rows}
    missing = [tid for tid in all_ids if tid not in done_ids]

    print(f"[*] 合并 {len(paths)} checkpoint, 去重 {len(rows)}/{len(all_ids)} 条"
          + (f", 缺失 {len(missing)}" if missing else ", 全覆盖 ✓"))

    # 逐 (attack x domain) 样本量
    cell = defaultdict(int)
    for r in rows:
        cell[(r["attack"], r["domain"])] += 1
    print("\n=== 逐 (attack x domain) 样本量 n ===")
    domains = A.DOMAINS
    print(f"{'attack':<16}" + "".join(f"{d:>10}" for d in domains))
    thin = []
    for atk in A.ATTACKS + ["benign"]:
        line = f"{atk:<16}"
        for d in domains:
            n = cell.get((atk, d), 0)
            line += f"{n:>10}"
            if atk != "benign" and n > 0 and n < 20:
                thin.append((atk, d, n))
        print(line)
    if thin:
        print("⚠ 样本 <20 的格 (官方任务 scarcity 须如实标注):")
        for atk, d, n in thin:
            print(f"   {atk} x {d} = {n}")
    else:
        print("✓ 所有攻击格 n>=20 (官方 scarcity 例外已单列)")

    # 逐 attack 聚合
    base = defaultdict(lambda: [0, 0])
    pq = defaultdict(lambda: [0, 0])
    bf = [0, 0]
    for r in rows:
        atk = r["attack"]
        base[atk][1] += 1; base[atk][0] += r["base_success"]
        pq[atk][1] += 1; pq[atk][0] += r["pq_success"]
        if r["kind"] == "benign":
            bf[1] += 1; bf[0] += r["pq_success"]

    print("\n=== 逐 attack 聚合 (真实 LLM, 官方任务) ===")
    print(f"{'attack':<16}{'baseline_ASR':>14}{'pqaib_ASR':>12}{'n':>7}")
    for atk in A.ATTACKS:
        s, n = base[atk]; ps, pn = pq[atk]
        print(f"{atk:<16}{s/n if n else 0:>14.3f}{ps/pn if pn else 0:>12.3f}{n:>7}")
    print(f"{'benign_FNR':<16}{'-':>14}{bf[0]/bf[1] if bf[1] else 0:>12.3f}{bf[1]:>7}")

    # 写聚合 CSV
    agg_csv = os.path.join(args.out, "full_combined_aggregate.csv")
    with open(agg_csv, "w", encoding="utf-8") as f:
        f.write("defense,attack,success,total,asr\n")
        for atk in A.ATTACKS:
            s, n = base[atk]; f.write(f"baseline,{atk},{s},{n},{s/n if n else 0:.4f}\n")
        for atk in A.ATTACKS:
            ps, pn = pq[atk]; f.write(f"pqaib,{atk},{ps},{pn},{ps/pn if pn else 0:.4f}\n")
        f.write(f"pqaib,benign_FNR,{bf[0]},{bf[1]},{bf[0]/bf[1] if bf[1] else 0:.4f}\n")
    print(f"[*] 聚合 -> {agg_csv}")

    # 写逐格 n CSV
    cell_csv = os.path.join(args.out, "full_by_cell_n.csv")
    with open(cell_csv, "w", encoding="utf-8") as f:
        f.write("attack,domain,n\n")
        for atk in A.ATTACKS + ["benign"]:
            for d in domains:
                f.write(f"{atk},{d},{cell.get((atk,d),0)}\n")
    print(f"[*] 逐格 n -> {cell_csv}")

    # 出图
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = A.ATTACKS
        basev = [base[a][0]/base[a][1] if base[a][1] else 0 for a in labels]
        pqv = [pq[a][0]/pq[a][1] if pq[a][1] else 0 for a in labels]
        x = range(len(labels)); w = 0.38
        fig, ax = plt.subplots(figsize=(9, 4.6))
        ax.bar([i-w/2 for i in x], basev, w, label="Baseline (no defense)", color="#c0392b")
        ax.bar([i+w/2 for i in x], pqv, w, label="PQ-AIB", color="#27ae60")
        ax.set_xticks(list(x)); ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=9)
        ax.set_ylabel("ASR (real LLM, official tasks)")
        ax.set_ylim(0, 1.05)
        ax.set_title(f"PQ-AIB vs Baseline — full A2ASecBench replay (n={len(rows)}, multi-backbone)")
        ax.legend()
        fig.tight_layout()
        png = os.path.join(args.out, "full_combined_asr.png")
        fig.savefig(png, dpi=120)
        print(f"[*] 图 -> {png}")
    except Exception as e:
        print(f"[WARN] 画图失败: {e}")


if __name__ == "__main__":
    main()
