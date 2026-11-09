#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 A2ASecBench 官方仓库提取任务定义 → 统一内部 schema。

★ 前置条件: 已克隆 https://github.com/SaFo-Lab/A2ASecBench
    cd A2ASecBench

★ 用法:
    python extract_official_tasks.py [--repo A2ASecBench] [-o a2asecbench_tasks.json]

★ 输出:
    - a2asecbench_tasks.json: 本项目可直接被 a2asecbench_adapter.load_tasks 消费的统一任务文件
    - 打印每攻击类型/每域的样本数统计

★ 两种提取模式:
    1. CASE_METADATA 模式 (asrf/atsi/co/hotf/cc_blackbox/cc_whitebox):
       任务定义在 Python 列表 CASE_METADATA 中, 每条含 case_id / domain / attack_id /
       environment / oracle 等结构化字段。用 ast.literal_eval 直接解析。
    2. 独立文件模式 (as/as_XXX.py):
       每个文件定义一个 ASCase 子类, 用 AST 提取 task_prompt / case_id / benign_choice。

★ 攻击类型映射 (官方 7 类 -> 内部 7 类):
    as         -> Spoofing              (AgentCard Spoofing)
    asrf       -> ASRF                   (Agent-Side Request Forgery)
    atsi       -> ATSI                   (Artifact-Triggered Script Injection)
    cc_blackbox-> Cloaking                (Capability Cloaking, blackbox)
    cc_whitebox-> Cloaking                (Capability Cloaking, whitebox)
    co         -> CycleOverflow          (Cycle Overflow)
    hotf       -> TaskFlooding           (Half-Open Task Flooding)
"""

import ast
import json
import os
import sys
from pathlib import Path
from collections import Counter, defaultdict

# 攻击类型映射
ATTACK_MAP = {
    "as": "Spoofing",
    "asrf": "ASRF",
    "atsi": "ATSI",
    "cc_blackbox": "Cloaking",
    "cc_whitebox": "Cloaking",
    "co": "CycleOverflow",
    "hotf": "TaskFlooding",
}

# 域关键词映射
DOMAIN_KEYWORDS = {
    "finance": ["finance", "financial", "bank", "payment", "revenue", "budget",
                "investment", "stock", "trade", "account", "loan", "credit", "insurance", "tax"],
    "healthcare": ["healthcare", "health", "medical", "patient", "hospital", "clinic",
                   "diagnosis", "treatment", "appointment", "prescription", "disease"],
    "travel": ["travel", "flight", "hotel", "booking", "trip", "vacation", "reservation",
               "itinerary", "transport", "ticket", "rental", "cruise", "fare"],
}

# 高风险能力映射 (按域)
HIGH_RISK = {
    "finance": "transfer_funds",
    "healthcare": "modify_patient_record",
    "travel": "cancel_hotel",
}


def infer_domain_from_metadata(case: dict) -> str:
    """从 CASE_METADATA 的 domain 字段 + 环境描述推断域。"""
    domain = case.get("domain", "").lower().strip()
    if domain in ("travel", "healthcare", "finance", "medical"):
        if domain == "medical":
            domain = "healthcare"
        return domain

    text = json.dumps(case, ensure_ascii=False).lower()
    scores = {}
    for d, keywords in DOMAIN_KEYWORDS.items():
        scores[d] = sum(1 for kw in keywords if kw in text)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "travel"


def _extract_case_prompt(case: dict) -> str:
    """从 CASE_METADATA 提取任务提示文本。"""
    env = case.get("environment", {})
    peer_msg = env.get("peer_message", "")
    if peer_msg:
        return peer_msg

    scenario = case.get("scenario", "")
    if scenario:
        return scenario

    public = case.get("public", {})
    agents = public.get("agents", [])
    if agents:
        return f"与 {agents[0].get('name', 'agent')} 交互: {agents[0].get('description', '')}"

    return case.get("case_id", "")


def _extract_oracle_event(case: dict) -> str:
    """从 oracle 提取期望的危害事件。"""
    oracle = case.get("oracle", {})
    return oracle.get("required_event", "")


def extract_from_case_metadata(source: str, attack_key: str) -> list[dict]:
    """从 CASE_METADATA 列表提取任务。"""
    internal_attack = ATTACK_MAP.get(attack_key, attack_key)
    tree = ast.parse(source)
    tasks = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id == "CASE_METADATA"):
                continue
            try:
                cases = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                continue

            for case in cases:
                if not isinstance(case, dict):
                    continue
                domain = infer_domain_from_metadata(case)
                prompt = _extract_case_prompt(case)
                oracle_event = _extract_oracle_event(case)
                target_cap = HIGH_RISK.get(domain, "query_balance")

                tasks.append({
                    "id": case.get("case_id", ""),
                    "domain": domain,
                    "kind": "adversarial",
                    "attack": internal_attack,
                    "target_capability": target_cap,
                    "user_prompt": f"[{domain}] <ADV> {prompt}",
                    "source": "official_a2asecbench",
                    "case_id": case.get("case_id", ""),
                    "difficulty": case.get("difficulty", ""),
                    "oracle_event": oracle_event,
                    "vector": case.get("vector", ""),
                    "is_control": case.get("is_control", False),
                })
            break

    return tasks


def extract_from_as_file(filepath: Path) -> list[dict]:
    """从 AS 独立 case 文件 (as_XXX.py) 提取任务。

    AS case 文件的格式为:
        class AS_001(ASCase):
            def __init__(self) -> None:
                super().__init__(case_id="as_001", task_prompt="...", benign_choice=1, ...)
    即 task_prompt / case_id / benign_choice 作为 super().__init__() 的关键字参数传入。
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            source = f.read()
    except Exception:
        return []

    tree = ast.parse(source)
    tasks = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        task_prompt = None
        case_id = None
        benign_choice = None

        for item in node.body:
            if not isinstance(item, ast.FunctionDef) or item.name != "__init__":
                continue
            for stmt in ast.walk(item):
                # 模式 1: 直接赋值 (旧格式)
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if not isinstance(target, ast.Name):
                            continue
                        if target.id == "task_prompt" and isinstance(stmt.value, ast.Constant):
                            task_prompt = stmt.value.value
                        elif target.id == "case_id" and isinstance(stmt.value, ast.Constant):
                            case_id = stmt.value.value
                        elif target.id == "benign_choice" and isinstance(stmt.value, ast.Constant):
                            benign_choice = stmt.value.value

                # 模式 2: super().__init__(...) 关键字参数 (实际格式)
                if isinstance(stmt, ast.Call):
                    func = stmt.func
                    # 匹配 super().__init__ 或 ASCase.__init__
                    is_super_init = (
                        isinstance(func, ast.Attribute)
                        and func.attr == "__init__"
                        and (
                            isinstance(func.value, ast.Call)
                            and isinstance(func.value.func, ast.Name)
                            and func.value.func.id == "super"
                            or isinstance(func.value, ast.Name)
                        )
                    )
                    if not is_super_init:
                        continue
                    for kw in stmt.keywords:
                        if kw.arg == "task_prompt" and isinstance(kw.value, ast.Constant):
                            task_prompt = kw.value.value
                        elif kw.arg == "case_id" and isinstance(kw.value, ast.Constant):
                            case_id = kw.value.value
                        elif kw.arg == "benign_choice" and isinstance(kw.value, ast.Constant):
                            benign_choice = kw.value.value

        if task_prompt:
            domain = infer_domain_from_text(task_prompt)
            tasks.append({
                "id": case_id or filepath.stem,
                "domain": domain,
                "kind": "adversarial",
                "attack": "Spoofing",
                "target_capability": HIGH_RISK.get(domain, "query_balance"),
                "user_prompt": f"[{domain}] <ADV> {task_prompt}",
                "source": "official_a2asecbench",
                "case_id": case_id or filepath.stem,
                "benign_choice": benign_choice or 1,
            })

    return tasks


def infer_domain_from_text(text: str) -> str:
    """从纯文本推断域。"""
    text_lower = text.lower()
    scores = {}
    for d, keywords in DOMAIN_KEYWORDS.items():
        scores[d] = sum(1 for kw in keywords if kw in text_lower)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "travel"


def extract_all(repo_path: str) -> list[dict]:
    """从 A2ASecBench 仓库提取所有任务。"""
    instances_dir = Path(repo_path) / "attacks" / "instances"
    if not instances_dir.is_dir():
        print(f"[错误] 找不到 {instances_dir}", file=sys.stderr)
        sys.exit(1)

    all_tasks = []
    stats = Counter()
    domain_stats = defaultdict(Counter)

    for attack_dir in sorted(instances_dir.iterdir()):
        if not attack_dir.is_dir():
            continue
        attack_key = attack_dir.name

        internal_attack = ATTACK_MAP.get(attack_key, attack_key)

        for py_file in sorted(attack_dir.glob("*.py")):
            # cc_blackbox / cc_whitebox: case 在 __init__.py 的 CASE_METADATA 中
            if py_file.name == "__init__.py":
                try:
                    with open(py_file, encoding="utf-8") as f:
                        source = f.read()
                    tasks = extract_from_case_metadata(source, attack_key)
                    if tasks:
                        for t in tasks:
                            all_tasks.append(t)
                            stats[internal_attack] += 1
                            domain_stats[internal_attack][t["domain"]] += 1
                        print(f"  {attack_key}/{py_file.name}: {len(tasks)} 条 (CASE_METADATA)")
                        continue
                except Exception:
                    pass

            # as_XXX.py: 独立 AS case 文件
            if py_file.name.startswith("as_") and py_file.name.endswith(".py"):
                tasks = extract_from_as_file(py_file)
                for t in tasks:
                    all_tasks.append(t)
                    stats[internal_attack] += 1
                    domain_stats[internal_attack][t["domain"]] += 1
                if tasks:
                    continue

            # executable.py: asrf/atsi/co/hotf 的 CASE_METADATA
            if py_file.name == "executable.py":
                try:
                    with open(py_file, encoding="utf-8") as f:
                        source = f.read()
                    tasks = extract_from_case_metadata(source, attack_key)
                    if tasks:
                        for t in tasks:
                            all_tasks.append(t)
                            stats[internal_attack] += 1
                            domain_stats[internal_attack][t["domain"]] += 1
                        print(f"  {attack_key}/{py_file.name}: {len(tasks)} 条 (CASE_METADATA)")
                except Exception as e:
                    print(f"  {attack_key}/{py_file.name}: 错误 - {e}")

    # 打印统计
    print(f"\n{'='*60}")
    print(f"提取统计")
    print(f"{'='*60}")
    total = sum(stats.values())
    print(f"总任务数: {total}")
    print(f"\n按攻击类型:")
    for atk in ["Spoofing", "ASRF", "ATSI", "Cloaking", "CycleOverflow", "TaskFlooding"]:
        n = stats.get(atk, 0)
        domains = ", ".join(
            f"{d}={domain_stats[atk][d]}"
            for d in ["travel", "healthcare", "finance"]
            if domain_stats[atk][d]
        )
        print(f"  {atk:20s}: {n:4d}  ({domains})")

    print(f"\n按域分布:")
    for domain in ["travel", "healthcare", "finance"]:
        n = sum(domain_stats[atk][domain] for atk in stats)
        print(f"  {domain}: {n}")

    return all_tasks


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="A2ASecBench", help="A2ASecBench 仓库路径")
    ap.add_argument("-o", "--out", default="a2asecbench_tasks.json", help="输出文件")
    args = ap.parse_args()

    tasks = extract_all(args.repo)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)

    print(f"\n[结果] 已写出 {len(tasks)} 条任务 -> {args.out}")
    print(f"[提示] 用 a2asecbench_adapter.py --data {args.out} 跑评测")


if __name__ == "__main__":
    main()