# -*- coding: utf-8 -*-
"""
merge_full_checkpoints.py -- 合并多端点分片 checkpoint -> 统一聚合 + 画图

读取 results/full_*.csv (逐任务 checkpoint, 表头含 task_id), 按 task_id 去重,
聚合 baseline / pqaib ASR 与 benign FNR; 同时给出逐 backbone 明细。

用法:
  python merge_full_checkpoints.py
  python merge_full_checkpoints.py --glob results/full_*.csv
"""
import argparse, csv, glob, os, sys
from collections import defaultdict
import a2asecbench_adapter as A

ATTACK_ORDER = A.ATTACKS


def load_rows(paths):
    rows = {}
    for p in paths:
        with open(p, encoding="utf-8") as f:
            r = csv.reader(f)
            header = next(r, None)
            if not header or header[0] != "task_id":
                continue  # 跳过聚合文件
            for row in r:
                if len(row) < 11:
                    continue
                tid = row[0]
                if tid in rows:
                    continue  # 去重: 同 task_id 仅计一次
                rows[tid] = {
                    "task_id": row[0], "attack": row[1], "domain": row[2],
                    "kind": row[3], "target_capability": row[4],
                    "base_tool": row[5], "base_success": int(row[6]),
                    "pq_decision": row[7], "pq_success": int(row[8]),
                    "base_adapt_success": row[9], "latency_s": float(row[10]),
                    "_src": os.path.basename(p),
                }
    return list(rows.values())


def aggregate(rows):
    # 总体
    agg = {"baseline": defaultdict(int), "pqaib": defaultdict(int),
           "benign_fnr": [0, 0], "baseline_adapt": defaultdict(int)}
    # 逐 backbone (由 checkpoint 文件名推断模型)
    by_model = defaultdict(lambda: {"baseline": defaultdict(int),
                                    "pqaib": defaultdict(int),
                                    "benign_fnr": [0, 0]})
    for r in rows:
        atk = r["attack"]
        model = _model_of(r["_src"])
        agg["baseline"][atk] += r["base_success"]
        agg["baseline"][atk + "_n"] = agg["baseline"].get(atk + "_n", 0) + 1
        agg["pqaib"][atk] += r["pq_success"]
        agg["pqaib"][atk + "_n"] = agg["pqaib"].get(atk + "_n", 0) + 1
        by_model[model]["baseline"][atk] += r["base_success"]
        by_model[model]["baseline"][atk + "_n"] = by_model[model]["baseline"].get(atk + "_n", 0) + 1
        by_model[model]["pqaib"][atk] += r["pq_success"]
        by_model[model]["pqaib"][atk + "_n"] = by_model[model]["pqaib"].get(atk + "_n", 0) + 1
        if r["kind"] == "benign":
            agg["benign_fnr"][1] += 1
            agg["benign_fnr"][0] += r["pq_success"]
            by_model[model]["benign_fnr"][1] += 1
            by_model[model]["benign_fnr"][0] += r["pq_success"]
        if r["base_adapt_success"] != "":
            agg["baseline_adapt"][atk] += int(r["base_adapt_success"])
            agg["baseline_adapt"][atk + "_n"] = agg["baseline_adapt"].get(atk + "_n", 0) + 1
    return agg, by_model


def _model_of(fname):
    # full_shard0_sensenova.csv -> sensenova ; full_sensenova.csv -> sensenova
    base = fname.replace("full_", "").replace(".csv", "")
    for tok in ["sensenova", "dots3", "agentsA1", "Agents-A1", "deepseek", "intern", "glm", "qwen"]:
        if tok.lower() in base.lower():
            return tok if tok != "agentsA1" else "Agents-A1"
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default="results/full_*.csv")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    paths = sorted(glob.glob(args.glob))
    rows = load_rows(paths)
    print(f"[*] 合并 {len(paths)} 个 checkpoint, 去重后 {len(rows)} 条任务")

    agg, by_model = aggregate(rows)

    # 写总体聚合 CSV
    out_csv = os.path.join(args.out, "full_combined_aggregate.csv")
    with open(out_csv, "w", encoding="utf-8") as f:
        f.write("defense,attack,success,total,asr\n")
        for atk in ATTACK_ORDER:
            s = agg["baseline"][atk]; n = agg["baseline"].get(atk + "_n", 0)
            f.write(f"baseline,{atk},{s},{n},{s/n if n else 0:.4f}\n")
        for atk in ATTACK_ORDER:
            s = agg["pqaib"][atk]; n = agg["pqaib"].get(atk + "_n", 0)
            f.write(f"pqaib,{atk},{s},{n},{s/n if n else 0:.4f}\n")
        bf_s, bf_n = agg["benign_fnr"]
        f.write(f"pqaib,benign_FNR,{bf_s},{bf_n},{bf_s/bf_n if bf_n else 0:.4f}\n")
    print(f"[*] 总体聚合 -> {out_csv}")

    # 逐 backbone 明细 CSV
    detail_csv = os.path.join(args.out, "full_by_model_aggregate.csv")
    with open(detail_csv, "w", encoding="utf-8") as f:
        f.write("model,attack,baseline_asr,pqaib_asr,n\n")
        for model in sorted(by_model):
            bm = by_model[model]
            for atk in ATTACK_ORDER:
                bs = bm["baseline"][atk]; bn = bm["baseline"].get(atk + "_n", 0)
                ps = bm["pqaib"][atk]; pn = bm["pqaib"].get(atk + "_n", 0)
                f.write(f"{model},{atk},{bs/bn if bn else 0:.4f},{ps/pn if pn else 0:.4f},{pn}\n")
    print(f"[*] 逐 backbone 明细 -> {detail_csv}")

    # 打印摘要
    print(f"\n=== 全量官方任务 真实 LLM 聚合 (n={len(rows)}) ===")
    print(f"{'attack':<16}{'baseline_ASR':>14}{'pqaib_ASR':>12}")
    for atk in ATTACK_ORDER:
        s = agg["baseline"][atk]; n = agg["baseline"].get(atk + "_n", 0)
        ps = agg["pqaib"][atk]; pn = agg["pqaib"].get(atk + "_n", 0)
        ba = s / n if n else 0
        pa = ps / pn if pn else 0
        print(f"{atk:<16}{ba:>14.3f}{pa:>12.3f}")
    bf_s, bf_n = agg["benign_fnr"]
    print(f"{'benign_FNR':<16}{'-':>14}{bf_s/bf_n if bf_n else 0:>12.3f}")

    # 画图
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = ATTACK_ORDER
        basev = [agg["baseline"][a]/agg["baseline"].get(a+"_n",0) if agg["baseline"].get(a+"_n",0) else 0 for a in labels]
        pqv = [agg["pqaib"][a]/agg["pqaib"].get(a+"_n",0) if agg["pqaib"].get(a+"_n",0) else 0 for a in labels]
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
