# -*- coding: utf-8 -*-
"""
run_all.py -- PQ-AIB 实验栈全链路离线回归（可复现性演示）。

★ 离线模式：LLM 走 --mock（确定性伪 LLM，零网络、零费用、零 GPU），
  一次性跑通论文全部可复现组件：
    1) A2ASecBench 风格回放 (PoC: 合成任务 × 7 类攻击, baseline vs PQ-AIB)
    2) 框架集成护栏演示 (LangGraph / AutoGen / A2A 三种 drop-in 形态, 8/8 一致性)
    3) 聚合 (merge_real 风格的 backbone×domain×attack 汇总)
  并对每一步做断言，任一失败即非零退出。

★ 真实 LLM 模式：去掉 --mock 即可（需 models.txt 中的可达端点），
  命令见《智能体安全_官方基准升级方案.md》与《智能体安全_无GPU方案.md》。

用法:
    python run_all.py                 # 离线全链路回归
    python run_all.py --real --model dots3-note-prev --domain finance --per 1
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run(cmd, check=True):
    print(f"\n$ {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    if r.stdout:
        print(r.stdout[-4000:])
    if r.stderr:
        print("[stderr]", r.stderr[-1500:])
    if check and r.returncode != 0:
        print(f"[FAIL] 命令退出码 {r.returncode}")
        sys.exit(r.returncode)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true", help="使用真实端点 (需网络+配额)")
    ap.add_argument("--model", default="dots3-note-prev")
    ap.add_argument("--domain", default="travel")
    ap.add_argument("--per", type=int, default=3)
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # 1) 回放 (PoC 离线 / 真实)
    cmd = [sys.executable, "a2asecbench_adapter.py",
           "--model", args.model, "--domain", args.domain,
           "--tasks", "1800", "--out", args.out]
    if not args.real:
        cmd.append("--mock")
    else:
        cmd += ["--per", str(args.per), "--delay", "2"]
    run(cmd)

    # 2) 框架护栏演示 (离线, 零依赖)
    run([sys.executable, "framework_guard.py"])

    # 3) 聚合
    run([sys.executable, "merge_real.py", "--out", os.path.join(args.out, "real_matrix.csv")])

    print("\n" + "=" * 66)
    print("全链路回归通过。产物:")
    for p in sorted(os.listdir(args.out)):
        if p.endswith(".csv") or p.endswith(".png"):
            print("  -", os.path.join(args.out, p))
    print("=" * 66)


if __name__ == "__main__":
    main()