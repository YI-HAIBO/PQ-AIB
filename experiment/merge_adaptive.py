# -*- coding: utf-8 -*-
"""
merge_adaptive.py -- 合并真实 LLM 自适应攻击者评测分片, 生成 Q1 用自适应表。

输入: run_full_checkpoint.py --adaptive 产出的分片 CSV
      (results/adapt_<model>_s<N>.csv), 列含 base_adapt_success
合并: 按 task_id 去重 -> 聚合 baseline / baseline_adapt / pqaib 三档 ASR
输出:
  results/adaptive_combined_aggregate.csv   攻击级聚合 (含 n 列)
  results/adaptive_by_model_aggregate.csv   按 backbone 分列
  results/adaptive_combined_asr.png         对比柱状图
"""
import argparse, csv, os
from collections import defaultdict


def load(path):
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append(r)
    return rows


def merge(rows):
    seen = {}
    for r in rows:
        tid = r.get("task_id")
        if tid not in seen:
            seen[tid] = r
    return list(seen.values())


def aggregate(rows):
    # attack -> defense -> [success, total]
    agg = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    per_model = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: [0, 0])))
    for r in rows:
        atk = r["attack"]
        model = r.get("model") or "?"
        # baseline
        agg["baseline"][atk][1] += 1
        per_model[model]["baseline"][atk][1] += 1
        if int(r["base_success"]):
            agg["baseline"][atk][0] += 1
            per_model[model]["baseline"][atk][0] += 1
        # pqaib
        agg["pqaib"][atk][1] += 1
        per_model[model]["pqaib"][atk][1] += 1
        if int(r["pq_success"]):
            agg["pqaib"][atk][0] += 1
            per_model[model]["pqaib"][atk][0] += 1
        # adaptive baseline
        if r.get("base_adapt_success", "") != "":
            agg["baseline_adapt"][atk][1] += 1
            per_model[model]["baseline_adapt"][atk][1] += 1
            if int(r["base_adapt_success"]):
                agg["baseline_adapt"][atk][0] += 1
                per_model[model]["baseline_adapt"][atk][0] += 1
    return agg, per_model


def rate(s, t):
    return s / t if t else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shards", nargs="+", required=True,
                    help="自适应分片 CSV 列表")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    all_rows = []
    for p in args.shards:
        all_rows += load(p)
    merged = merge(all_rows)
    agg, per_model = aggregate(merged)

    # 攻击级聚合
    combined = os.path.join(args.out, "adaptive_combined_aggregate.csv")
    with open(combined, "w", encoding="utf-8") as f:
        f.write("defense,attack,success,total,asr\n")
        for defense in ["baseline", "baseline_adapt", "pqaib"]:
            for atk, (s, t) in sorted(agg[defense].items()):
                f.write(f"{defense},{atk},{s},{t},{rate(s,t):.4f}\n")

    # 按 backbone 分列
    by_model = os.path.join(args.out, "adaptive_by_model_aggregate.csv")
    with open(by_model, "w", encoding="utf-8") as f:
        f.write("model,defense,attack,success,total,asr\n")
        for model in sorted(per_model):
            for defense in ["baseline", "baseline_adapt", "pqaib"]:
                for atk, (s, t) in sorted(per_model[model][defense].items()):
                    f.write(f"{model},{defense},{atk},{s},{t},{rate(s,t):.4f}\n")

    # 打印摘要
    print(f"\n=== 真实 LLM 自适应攻击评估 (合并 {len(merged)} 条唯一任务) ===")
    print(f"{'attack':<14}{'baseline':>10}{'baseline_adapt':>16}{'pqaib':>10}")
    for atk in sorted(agg["baseline"]):
        b = rate(*agg["baseline"][atk])
        a = rate(*agg["baseline_adapt"][atk])
        p = rate(*agg["pqaib"][atk])
        print(f"{atk:<14}{b:>10.3f}{a:>16.3f}{p:>10.3f}")
    bn = agg["pqaib"].get("benign", [0, 0])
    print(f"{'benign_FNR':<14}{'-':>10}{'-':>16}{rate(*bn):>10.3f}")

    # 图表
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        attacks = sorted(agg["baseline"])
        base = [rate(*agg["baseline"][a]) for a in attacks]
        adapt = [rate(*agg["baseline_adapt"][a]) for a in attacks]
        pq = [rate(*agg["pqaib"][a]) for a in attacks]
        x = range(len(attacks)); w = 0.27
        fig, ax = plt.subplots(figsize=(10, 4.6))
        ax.bar([i - w for i in x], base, w, label="Baseline (static)", color="#c0392b")
        ax.bar([i for i in x], adapt, w, label="Baseline (adaptive)", color="#e67e22")
        ax.bar([i + w for i in x], pq, w, label="PQ-AIB", color="#27ae60")
        ax.set_xticks(list(x)); ax.set_xticklabels(attacks, rotation=30, ha="right", fontsize=8)
        ax.set_ylabel("ASR"); ax.set_ylim(0, 1.05)
        ax.set_title("A2ASecBench official tasks — real LLM, adaptive adversary")
        ax.legend(); fig.tight_layout()
        png = os.path.join(args.out, "adaptive_combined_asr.png")
        fig.savefig(png, dpi=120); print(f"图表 -> {png}")
    except Exception as e:
        print(f"[skip chart] {e}")

    print(f"\n聚合 -> {combined}\n按 backbone -> {by_model}")


if __name__ == "__main__":
    main()
