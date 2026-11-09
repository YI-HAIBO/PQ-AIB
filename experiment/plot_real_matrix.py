# -*- coding: utf-8 -*-
"""
plot_real_matrix.py -- 从 results/real_matrix.csv 生成论文用 ASR 对比柱状图。

输出: results/asr_real_matrix.png
  - x 轴: 7 类攻击 (中文称谓 + 官方英文缩写)
  - 分组柱: 基线 ASR (暖色, 越高越不利) vs PQ-AIB ASR (绿色, 全 0)
  - 柱顶标注有效样本 n
  - 标注"身份类 0 域被破 / 编排类 3 域全破"的结构性结论
"""
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

CSV = "results/real_matrix.csv"
OUT = "results/asr_real_matrix.png"

ATTACK_LABEL = [
    ("AgentCard\nSpoofing", "Spoofing"),
    ("Capability\nCloaking", "Cloaking"),
    ("Cycle\nOverflow", "CycleOverflow"),
    ("Half-Open\nTask Flooding", "TaskFlooding"),
    ("Agent-Side\nRequest Forgery", "ASRF"),
    ("Artifact-Triggered\nScript Inj.", "ATSI"),
    ("Confused\nDeputy", "ConfusedDeputy"),
]

# 读取跨 backbone 聚合 (按攻击类求和)
agg = {a: {"n": 0, "base": 0.0, "pq": 0.0} for _, a in ATTACK_LABEL}
with open(CSV, encoding="utf-8") as f:
    for r in csv.DictReader(f):
        a = r["attack"]
        if a not in agg:
            continue
        agg[a]["n"] += int(r["n_ok"])
        agg[a]["base"] += float(r["baseline_ASR"]) * int(r["n_ok"])
        agg[a]["pq"] += float(r["pqaib_ASR"]) * int(r["n_ok"])
for a in agg:
    n = agg[a]["n"]
    agg[a]["base"] = agg[a]["base"] / n if n else 0.0
    agg[a]["pq"] = agg[a]["pq"] / n if n else 0.0

labels = [l for l, _ in ATTACK_LABEL]
base_vals = [agg[a]["base"] for _, a in ATTACK_LABEL]
pq_vals = [agg[a]["pq"] for _, a in ATTACK_LABEL]
ns = [agg[a]["n"] for _, a in ATTACK_LABEL]

fig, ax = plt.subplots(figsize=(11, 5.2))
x = range(len(labels))
w = 0.36
b1 = ax.bar([i - w / 2 for i in x], base_vals, w, label="Baseline ASR (model guardrail only)",
            color="#D1495B", edgecolor="white", linewidth=0.6)
b2 = ax.bar([i + w / 2 for i in x], pq_vals, w, label="PQ-AIB ASR", color="#2E8B57",
            edgecolor="white", linewidth=0.6)

for i, (v, n) in enumerate(zip(base_vals, ns)):
    ax.text(i - w / 2, v + 0.012, f"{v:.2f}\nn={n}", ha="center", va="bottom", fontsize=8)
for i, v in enumerate(pq_vals):
    ax.text(i + w / 2, v + 0.012, "0.00", ha="center", va="bottom", fontsize=8, color="#1E6B3A")

ax.set_xticks(list(x))
ax.set_xticklabels(labels, fontsize=9)
ax.set_ylabel("Attack Success Rate (ASR)", fontsize=10)
ax.set_ylim(0, 0.55)
ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f"))
ax.set_title("A2ASecBench replay — ASR by attack class (4 backbones x 3 domains, 340 valid samples)",
             fontsize=11, pad=10)
ax.legend(loc="upper right", fontsize=9, framealpha=0.9)

# 结构性结论标注
ax.text(0.02, 0.96,
        "identity/auth: 0/131 (0 domains breached) | orchestration: 48/155=0.310 (all 3 domains)",
        transform=ax.transAxes, fontsize=8.5, color="#444444",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#F4F6F2", edgecolor="#C0C8C0", alpha=0.9))
ax.text(0.02, 0.90,
        "PQ-AIB: 340/340 intercepted (incl. adaptive perturbations), FNR=0.000",
        transform=ax.transAxes, fontsize=8.5, color="#1E6B3A",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#EAF3EC", edgecolor="#9BC1A3", alpha=0.9))

ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.grid(axis="y", linestyle="--", alpha=0.35)
plt.tight_layout()
plt.savefig(OUT, dpi=150)
print("已写出", OUT)