# -*- coding: utf-8 -*-
"""
run_full_official.py -- 全量 1100 条官方任务 × 真实 LLM × 自适应 + 扩样本
                        (Windows / Linux 通用，无需 bash)

用法:
  python run_full_official.py                          # 官方 backbone × 全量 1100
  python run_full_official.py --model dots3-note-prev  # 指定第三方 backbone
  python run_full_official.py --expand 20              # 额外扩样本 n≥20/类
  python run_full_official.py --expand 20 --model sensenova-6.8-flash-lite

前置:
  - a2asecbench_tasks.json 在上级目录 (495KB, 1100 条)
  - 官方 backbone 需先运行 setup_official_backbones.py + export 密钥
"""
import argparse, os, subprocess, sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)


def run(cmd, desc):
    """运行命令，打印进度，失败时抛出异常。"""
    print(f"\n{'='*60}")
    print(f" [{desc}]")
    print(f" {' '.join(cmd)}")
    print(f"{'='*60}")
    sys.stdout.flush()
    result = subprocess.run(cmd, cwd=SCRIPT_DIR, capture_output=False)
    if result.returncode != 0:
        print(f"[FAIL] {desc} 退出码={result.returncode}")
        sys.exit(result.returncode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt-4o", help="models.txt 中的模型 id")
    ap.add_argument("--expand", type=int, default=0, help="扩样本 n/类 (0=不扩)")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    data_path = os.path.join(PROJECT_DIR, "a2asecbench_tasks.json")
    if not os.path.exists(data_path):
        print(f"[ERR] 找不到 {data_path}"); sys.exit(1)

    print(f"==============================================")
    print(f" 全量官方基准评测")
    print(f" 模型: {args.model}")
    print(f" 任务: a2asecbench_tasks.json (1100 条)")
    print(f" 自适应: 是")
    if args.expand:
        print(f" 扩样本: n≥{args.expand}/类")
    print(f"==============================================")

    # --- 第 1 步: 全量 1100 × 自适应 ---
    run([
        sys.executable, "a2asecbench_adapter.py",
        "--model", args.model,
        "--domain", "all",
        "--data", data_path,
        "--adaptive",
        "--delay", str(args.delay),
        "--out", args.out,
    ], "官方任务全量评测")

    # --- 第 2 步: 聚合 ---
    run([sys.executable, "merge_real.py"], "聚合结果")

    # --- 第 3 步（可选）: 扩样本 ---
    if args.expand > 0:
        for dom in ["travel", "healthcare", "finance"]:
            run([
                sys.executable, "quick_real.py",
                "--model", args.model,
                "--domain", dom,
                "--per", str(args.expand),
                "--adaptive",
                "--delay", str(args.delay),
                "--out", args.out,
            ], f"扩样本 n={args.expand} ({dom})")
        run([sys.executable, "merge_real.py"], "聚合结果（含扩样本）")

    print(f"\n==============================================")
    print(f" 完成。结果文件:")
    print(f"   results/a2asecbench_{args.model}_all.csv")
    print(f"   results/a2asecbench_{args.model}_all_adapt.csv")
    print(f"   results/real_matrix.csv")
    print(f"==============================================")


if __name__ == "__main__":
    main()