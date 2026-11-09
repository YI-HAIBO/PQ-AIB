# -*- coding: utf-8 -*-
"""
merge_real.py  --  汇总 quick_real_*.csv 为论文表 (backbone × domain × attack)

用法: python merge_real.py [--out results/real_matrix.csv]
输出:
  1) 逐 backbone×domain×attack 的 baseline ASR / PQ-AIB ASR
  2) 每 backbone 汇总
  3) 逐攻击类型跨 backbone 汇总 (暴露"护栏措辞依赖")
  4) 良性 FNR
剔除 ERR(端点配额失败)样本, 并在 n_ok 中报告有效样本数。
"""
import csv, glob, os, collections, argparse, json

ATTACKS = ["Spoofing", "Cloaking", "CycleOverflow", "TaskFlooding",
           "ASRF", "ATSI", "ConfusedDeputy"]


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/real_matrix.csv")
    ap.add_argument("--pattern", default="results/quick_real_*.csv")
    args = ap.parse_args()

    files = sorted(glob.glob(args.pattern))
    if not files:
        print("[ERR] 无 quick_real_*.csv"); return
    allrows = []
    for p in files:
        allrows += load(p)
    print(f"读入 {len(files)} 个文件, {len(allrows)} 行: {[os.path.basename(x) for x in files]}\n")

    # --- 1) backbone × domain × attack ---
    agg = collections.defaultdict(lambda: {"n": 0, "err": 0, "base_hit": 0, "pq_hit": 0})
    benign = collections.defaultdict(lambda: {"n": 0, "blocked": 0})
    adapt = collections.defaultdict(lambda: {"base": 0, "pq": 0, "n": 0})

    for r in allrows:
        m, d, a = r["model"], r["domain"], r["attack"]
        if r["id"] == "adaptive":
            adapt[(m, d, a)]["base"] += int(r["baseline_hit"])
            adapt[(m, d, a)]["pq"] += int(r["pq_hit"])
            adapt[(m, d, a)]["n"] += 1
            continue
        if r["kind"] == "benign":
            benign[(m, d)]["n"] += 1
            benign[(m, d)]["blocked"] += int(r["benign_blocked"])
            continue
        k = (m, d, a)
        if str(r["baseline_tool"]).startswith("ERR"):
            agg[k]["err"] += 1
            continue
        agg[k]["n"] += 1
        agg[k]["base_hit"] += int(r["baseline_hit"])
        agg[k]["pq_hit"] += int(r["pq_hit"])

    print("=" * 78)
    print("【表 1】backbone × domain × attack（ERR 已剔除）")
    print(f"{'model':<22}{'domain':<12}{'attack':<15}{'n':>3}{'base_ASR':>10}{'pq_ASR':>9}")
    print("-" * 78)
    for (m, d, a) in sorted(agg):
        v = agg[(m, d, a)]
        if not v["n"]:
            continue
        print(f"{m:<22}{d:<12}{a:<15}{v['n']:>3}"
              f"{v['base_hit']/v['n']:>10.3f}{v['pq_hit']/v['n']:>9.3f}")

    # --- 2) 每 backbone 汇总 ---
    print("\n" + "=" * 78)
    print("【表 2】每 backbone 汇总")
    print(f"{'model':<22}{'n':>5}{'base_ASR':>10}{'pq_ASR':>9}{'FNR':>8}{'adapt_base':>12}{'adapt_pq':>10}")
    print("-" * 78)
    per_model = collections.defaultdict(lambda: {"n": 0, "bh": 0, "ph": 0, "ab": 0, "ap": 0, "an": 0})
    err_model = collections.defaultdict(int)
    for (m, d, a), v in agg.items():
        per_model[m]["n"] += v["n"]; per_model[m]["bh"] += v["base_hit"]; per_model[m]["ph"] += v["pq_hit"]
        err_model[m] += v["err"]
    for (m, d, a), v in adapt.items():
        per_model[m]["ab"] += v["base"]; per_model[m]["ap"] += v["pq"]; per_model[m]["an"] += v["n"]
    fnr = collections.defaultdict(lambda: [0, 0])
    for (m, d), v in benign.items():
        fnr[m][0] += v["blocked"]; fnr[m][1] += v["n"]
    for m in sorted(per_model):
        v = per_model[m]
        f = (fnr[m][0] / fnr[m][1]) if fnr[m][1] else 0
        ab = f"{v['ab']}/{v['an']}" if v["an"] else "-"
        if v["n"] == 0:
            print(f"{m:<22}{0:>5}{'无效':>10}{'无效':>9}{'-':>8}{ab:>12}"
                  f"   [!! 全部 {err_model[m]} 次调用 ERR，该 backbone 结果不可用]")
            continue
        print(f"{m:<22}{v['n']:>5}{v['bh']/v['n']:>10.3f}{v['ph']/v['n']:>9.3f}{f:>8.3f}{ab:>12}{v['ap']:>10}"
              f"   (ERR={err_model[m]})")

    # --- 3) 逐攻击类型跨 backbone（护栏措辞依赖） ---
    print("\n" + "=" * 78)
    print("【表 3】逐攻击类型跨 backbone（暴露护栏措辞依赖）")
    print(f"{'attack':<15}{'n':>4}{'base_ASR':>10}{'pq_ASR':>9}{'突破域数':>9}")
    print("-" * 78)
    per_atk = collections.defaultdict(lambda: {"n": 0, "bh": 0, "ph": 0})
    dom_hit = collections.defaultdict(set)
    for (m, d, a), v in agg.items():
        if not v["n"]:
            continue
        per_atk[a]["n"] += v["n"]
        per_atk[a]["bh"] += v["base_hit"]
        per_atk[a]["ph"] += v["pq_hit"]
        if v["base_hit"]:
            dom_hit[a].add(d)
    for a in ATTACKS:
        v = per_atk.get(a)
        if not v or not v["n"]:
            continue
        print(f"{a:<15}{v['n']:>4}{v['bh']/v['n']:>10.3f}{v['ph']/v['n']:>9.3f}{len(dom_hit.get(a,set())):>9}")

    # --- 写 CSV ---
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["model", "domain", "attack", "n_ok", "baseline_ASR", "pqaib_ASR",
                    "adaptive_base", "adaptive_pq"])
        for (m, d, a) in sorted(agg):
            v = agg[(m, d, a)]
            if not v["n"]:
                continue
            ad = adapt.get((m, d, a), {"base": 0, "pq": 0, "n": 0})
            w.writerow([m, d, a, v["n"], f"{v['base_hit']/v['n']:.3f}", f"{v['pq_hit']/v['n']:.3f}",
                        ad["base"], ad["pq"]])
    print(f"\n论文矩阵 -> {args.out}")


if __name__ == "__main__":
    main()
