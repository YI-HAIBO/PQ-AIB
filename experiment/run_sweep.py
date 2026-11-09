# -*- coding: utf-8 -*-
"""
run_sweep.py  --  全量扫描批处理 (models.txt 全部端点 x 3 域, 含自适应)

在合作方 GPU / 直连网络环境执行:
    python run_sweep.py                    # 真实端点, 全部模型 x 全部域
    python run_sweep.py --mock             # 离线自检 (0 成本)
    python run_sweep.py --models deepseek-v4-flash,glm-5.3 --domains travel,finance
    python run_sweep.py --delay 2 --out results

逐模型逐域调用 a2asecbench_adapter.py --adaptive, 生成:
    results/a2asecbench_<model>_<domain>.csv
    results/a2asecbench_<model>_<domain>_adapt.csv
    results/a2asecbench_<model>_<domain>.png
最后汇总到 results/sweep_summary.log 与 results/sweep_matrix.csv。
跑完后执行 python summarize.py 生成论文汇总表。
"""
import argparse, json, os, subprocess, sys, time, csv, collections, glob

DOMAINS = ["travel", "healthcare", "finance"]


def load_models(path="models.txt"):
    with open(path, encoding="utf-8") as f:
        return [m["id"] for m in json.load(f)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true", help="离线模拟 (无网络/无费用)")
    ap.add_argument("--models", default="", help="逗号分隔模型 id 子集; 空=全部")
    ap.add_argument("--domains", default="all", help="逗号分隔域子集 或 all")
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    models = load_models()
    if args.models:
        want = set(args.models.split(","))
        models = [m for m in models if m in want]
    domains = DOMAINS if args.domains == "all" else args.domains.split(",")

    os.makedirs(args.out, exist_ok=True)
    log_path = os.path.join(args.out, "sweep_summary.log")
    summary = []

    with open(log_path, "w", encoding="utf-8") as log:
        log.write(f"# PQ-AIB full sweep  {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log.write(f"# mode={'MOCK' if args.mock else 'REAL'}  models={models}  domains={domains}\n\n")
        for m in models:
            for d in domains:
                cmd = [sys.executable, "a2asecbench_adapter.py",
                       "--model", m, "--domain", d, "--adaptive",
                       "--delay", str(args.delay), "--out", args.out]
                if args.mock:
                    cmd.append("--mock")
                print(f"\n>>> [{m} | {d}] " + ("MOCK" if args.mock else "REAL"))
                t0 = time.time()
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                    ok = r.returncode == 0
                    tail = (r.stdout.strip().splitlines() or [""])[-1]
                except subprocess.TimeoutExpired:
                    ok, tail = False, "TIMEOUT"
                dt = time.time() - t0
                print(f"    {'OK' if ok else 'FAIL'}  {tail}  ({dt:.0f}s)")
                log.write(f"{m},{d},{'OK' if ok else 'FAIL'},{dt:.1f}s\n")
                log.flush()
                summary.append({"model": m, "domain": d, "ok": ok, "secs": round(dt, 1)})

    # 汇总矩阵 CSV
    mat = os.path.join(args.out, "sweep_matrix.csv")
    with open(mat, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["model", "domain", "status", "secs"])
        for s in summary:
            w.writerow([s["model"], s["domain"], "OK" if s["ok"] else "FAIL", s["secs"]])
    print(f"\n扫描矩阵 -> {mat}  汇总日志 -> {log_path}")
    print("完成: 下一步运行  python summarize.py  生成论文汇总表。")


if __name__ == "__main__":
    main()
