#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构建 4-backbone 跨模型一致性表：
  - 列1: 3 个沙箱 backbone 合并全量 (sensenova/dots3/Agents-A1) -> full_combined_aggregate.csv
  - 列2: deepseek-v4-flash 全量基线 (强模型代理) -> full_deepseek-v4-flash_baseline.csv (续跑中)
  - 列3: PQ-AIB (协议层, 确定性, 全 0)
输出 results/full_4backbone_table.csv + 终端 markdown。
deepseek 未完成时按"已评测条数/1100"标注进度, 不谎报。
"""
import csv, os

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
COMB = os.path.join(RES, "full_combined_aggregate.csv")
DEEP = os.path.join(RES, "full_deepseek-v4-flash_baseline.csv")
OUT = os.path.join(RES, "full_4backbone_table.csv")

ATTACKS = ["Spoofing", "Cloaking", "CycleOverflow", "TaskFlooding", "ASRF", "ATSI", "ConfusedDeputy"]


def load_combined():
    """返回 {attack: (base_asr, pqaib_asr, base_total)}"""
    d = {}
    with open(COMB, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["attack"] == "ConfusedDeputy" and r["defense"] == "baseline" and int(r["total"]) == 0:
                continue
            try:
                asr = float(r["asr"])
            except ValueError:
                asr = 0.0
            d.setdefault(r["attack"], {})[r["defense"]] = (asr, int(r["total"]))
    return d


def load_deepseek():
    """返回 {attack: (success, total)} 仅 baseline 列 (base_success)"""
    d = {}
    if not os.path.exists(DEEP):
        return d, 0
    n = 0
    with open(DEEP, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            n += 1
            atk = r.get("attack", "")
            try:
                ok = int(r.get("base_success") or 0)
            except ValueError:
                ok = 0
            e = d.setdefault(atk, [0, 0])
            e[0] += ok
            e[1] += 1
    return d, n


def main():
    comb = load_combined()
    deep, deep_n = load_deepseek()

    rows = []
    tot_base3_s = tot_base3_t = 0
    tot_deep_s = tot_deep_t = 0
    for atk in ATTACKS:
        if atk == "ConfusedDeputy":
            continue
        b3 = comb.get(atk, {}).get("baseline", (0.0, 0))
        pqaib = comb.get(atk, {}).get("pqaib", (0.0, 0))
        b3_asr, b3_t = b3
        pq_asr, _ = pqaib
        d_s, d_t = deep.get(atk, [0, 0])
        rows.append((atk, b3_asr, b3_t, (d_s / d_t) if d_t else None, d_t, pq_asr))
        tot_base3_s += 0  # asr 已百分比, 聚合另算
        tot_deep_s += d_s
        tot_deep_t += d_t

    # 聚合行
    base3_total_all = sum(comb.get(a, {}).get("baseline", (0, 0))[1] for a in ATTACKS if a != "ConfusedDeputy")
    base3_succ_all = sum(
        int(float(comb.get(a, {}).get("baseline", (0, 0))[0]) * comb.get(a, {}).get("baseline", (0, 0))[1])
        for a in ATTACKS if a != "ConfusedDeputy"
    )
    agg_base3 = base3_succ_all / base3_total_all if base3_total_all else 0.0

    # 写 CSV
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["attack", "base3_asr", "base3_n", "deepseek_asr", "deepseek_n", "pqaib_asr"])
        for atk, b3a, b3t, da, dt, pqa in rows:
            w.writerow([atk, f"{b3a:.4f}", b3t,
                        (f"{da:.4f}" if da is not None else "NA"), (dt if dt else 0), f"{pqa:.4f}"])
        w.writerow(["AGG", f"{agg_base3:.4f}", base3_total_all,
                    (f"{tot_deep_s/tot_deep_t:.4f}" if tot_deep_t else "NA"), tot_deep_t, "0.0000"])

    # 终端 markdown
    print("\n## 4-Backbone 跨模型一致性表 (PQ-AIB 评测)")
    print(f"- 列A: 3 沙箱 backbone 合并全量 (sensenova/dots3/Agents-A1), n={base3_total_all}")
    print(f"- 列B: deepseek-v4-flash 强模型代理, 进度 {deep_n}/1100" + (" (续跑中)" if deep_n < 1100 else " (完成)"))
    print(f"- 列C: PQ-AIB (协议层确定性网关, 全 0)\n")
    print("| 攻击 | 3-backbone 基线 ASR | deepseek 基线 ASR | PQ-AIB ASR |")
    print("|---|---|---|---|")
    for atk, b3a, b3t, da, dt, pqa in rows:
        da_s = f"{da:.4f} (n={dt})" if da is not None else f"NA (n={dt})"
        print(f"| {atk} | {b3a:.4f} | {da_s} | {pqa:.4f} |")
    agg_da = f"{tot_deep_s/tot_deep_t:.4f}" if tot_deep_t else "NA"
    print(f"| **聚合** | **{agg_base3:.4f}** | **{agg_da}** (n={tot_deep_t}) | **0.0000** |")
    print(f"\n-> 写出 {OUT}")


if __name__ == "__main__":
    main()
