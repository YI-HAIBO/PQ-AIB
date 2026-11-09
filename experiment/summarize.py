# -*- coding: utf-8 -*-
"""
summarize.py  --  聚合 a2asecbench_*.csv 为论文表格 (backbone x domain x attack)

读取 results/a2asecbench_<model>_<domain>.csv, 按 模型(backbone) x domain 分组,
输出每类攻击的 baseline ASR / PQ-AIB ASR / 降幅%, 并生成论文级汇总表。

用法:
    python summarize.py [--in results] [--out results]

真实全量数据在合作方 GPU 环境跑出后, 重新运行本脚本即可自动回填论文表格。
"""
import argparse, os, glob, re, csv, json, collections

ATTACKS = ["Spoofing", "Cloaking", "CycleOverflow", "TaskFlooding",
           "ASRF", "ATSI", "ConfusedDeputy"]


def parse_csv(path):
    """返回 dict[defense][attack] -> asr"""
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 5 or parts[0] == "defense":
                continue
            defense, attack = parts[0], parts[1]
            asr = float(parts[4])
            rows.setdefault(defense, {})[attack] = asr
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="results")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    files = glob.glob(os.path.join(args.indir, "a2asecbench_*.csv"))
    files = [f for f in files if "aggregate" not in os.path.basename(f)]
    if not files:
        print("无 a2asecbench_*.csv 可聚合"); return

    agg = []   # (model, domain, attack, base, pq, reduction)
    for f in sorted(files):
        base = os.path.basename(f)
        m = re.match(r"a2asecbench_(.+)_(travel|healthcare|finance|all)\.csv", base)
        if not m:
            continue
        model, domain = m.group(1), m.group(2)
        rows = parse_csv(f)
        for atk in ATTACKS:
            b = rows.get("baseline", {}).get(atk, float("nan"))
            p = rows.get("pqaib", {}).get(atk, float("nan"))
            red = (1 - p / b) * 100 if (b and b > 0) else float("nan")
            agg.append((model, domain, atk, b, p, red))

    # 写聚合 CSV
    os.makedirs(args.out, exist_ok=True)
    out_csv = os.path.join(args.out, "a2asecbench_aggregate.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["backbone", "domain", "attack", "asr_baseline", "asr_pqaib", "reduction_pct"])
        for r in agg:
            w.writerow([r[0], r[1], r[2], f"{r[3]:.4f}", f"{r[4]:.4f}", f"{r[5]:.1f}"])
    print(f"聚合结果 -> {out_csv}")

    # 按模型分组输出论文表 (markdown)
    by_model = collections.OrderedDict()
    for r in agg:
        by_model.setdefault(r[0], collections.OrderedDict()).setdefault(r[1], {})[r[2]] = r
    print("\n=== 论文汇总表骨架 (backbone x domain x attack) ===")
    for model, doms in by_model.items():
        for dom, atks in doms.items():
            print(f"\n[{model} | {dom}]")
            print(f"{'attack':<16}{'ASR_base':>10}{'ASR_PQ':>10}{'reduction':>12}")
            for atk in ATTACKS:
                r = atks.get(atk)
                if not r:
                    continue
                print(f"{atk:<16}{r[3]:>10.3f}{r[4]:>10.3f}{r[5]:>11.1f}%")


if __name__ == "__main__":
    main()
