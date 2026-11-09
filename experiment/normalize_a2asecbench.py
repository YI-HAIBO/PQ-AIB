#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把官方 A2ASecBench 任务文件归一化为本项目内部 schema。

用法 (在克隆了 https://github.com/SaFo-Lab/A2ASecBench 的机器上):
    python normalize_a2asecbench.py <官方任务文件.json> [-o a2asecbench_tasks.json]

特性:
  - 自动探查官方文件的顶层结构与首条记录字段, 打印出来供确认。
  - 复用 a2asecbench_adapter._norm_task 的容忍式字段映射
    (domain/scenario, kind/type/split, attack/attack_type/threat,
     user_prompt/prompt/instruction, target_capability/target_tool/capability)。
  - 攻击名按 OFFICIAL_ATTACK_MAP 归一化到内部 7 类 (官方 6 + ConfusedDeputy)。
  - 输出本项目可直接被 load_tasks 消费的 a2asecbench_tasks.json。
  - 统计每域/每攻击的样本数, 方便判断样本量是否足够 (投稿前建议 n>=20/类)。
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2asecbench_adapter import _norm_task, ATTACKS, DOMAINS  # noqa: E402


def inspect(raw):
    if isinstance(raw, dict):
        print(f"[结构] 顶层为 dict, 键: {list(raw.keys())[:20]}")
        items = raw.get("tasks") or raw.get("data") or raw.get("examples") or []
    else:
        items = raw
    print(f"[结构] 记录数: {len(items)}")
    if items:
        print(f"[结构] 首条字段: {list(items[0].keys())}")
        print(f"[结构] 首条样例: {json.dumps(items[0], ensure_ascii=False)[:400]}")
    return items


def main():
    if len(sys.argv) < 2:
        print("用法: python normalize_a2asecbench.py <官方任务文件.json> [-o 输出.json]",
              file=sys.stderr)
        sys.exit(2)
    src = sys.argv[1]
    out = "a2asecbench_tasks.json"
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]

    with open(src, encoding="utf-8") as f:
        raw = json.load(f)
    items = inspect(raw)

    norm, skipped = [], 0
    per_domain, per_attack = {}, {}
    for t in items:
        nt = _norm_task(t)
        if nt is None:
            skipped += 1
            continue
        norm.append(nt)
        per_domain[nt["domain"]] = per_domain.get(nt["domain"], 0) + 1
        if nt["attack"]:
            per_attack[nt["attack"]] = per_attack.get(nt["attack"], 0) + 1

    with open(out, "w", encoding="utf-8") as f:
        json.dump(norm, f, ensure_ascii=False, indent=2)

    print(f"\n[结果] 归一化 {len(norm)} 条, 跳过 {skipped} 条")
    print(f"[结果] 每域: {per_domain}")
    print(f"[结果] 每攻击(内部名): {per_attack}")
    print(f"[结果] 已写出 -> {out}")
    print("[提示] 用 a2asecbench_adapter.py --data", out, "跑评测")


if __name__ == "__main__":
    main()
