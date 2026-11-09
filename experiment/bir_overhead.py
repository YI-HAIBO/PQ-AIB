# -*- coding: utf-8 -*-
"""
bir_overhead.py  --  BIR 链上开销量化 (建模, 非真实链实测)

量化 PQ-AIB 中区块链身份注册表(BIR)的操作开销:
  注册(门限签发+上链确认) / 撤销 / 发现(链读+验签) / 握手(2签+2验) / 调用(1签+1验)
参数: 签名开销(Ed25519实测 + Dilithium文献) x 联盟链参数(块时间/门限M/N/确认深度)。

诚实声明: 这是"设计阶段开销模型"——签名时间用实测/文献值, 链参数为典型联盟链假设
(如 Hyperledger Fabric / 联盟链 1-5s 块时间, 2 块确认)。非真实链上实测; 论文中须标注
为模型估计, 真实链上吞吐留待部署实测。

运行: python bir_overhead.py [--out results]
"""
import argparse, os, csv

# ---- 签名开销 (实测/文献, 毫秒) -------------------------------------------
SIG = {
    "Ed25519":   {"sign": 0.0525, "verify": 0.1217},
    "P256":      {"sign": 0.0327, "verify": 0.0742},
    "Dilithium": {"sign": 1.50,   "verify": 0.30},   # 文献量级 (1-2ms sign, 0.1-0.5 verify)
}
# ---- 联盟链典型参数 ---------------------------------------------------------
BLOCK_TIMES = [1, 2, 5]        # 秒/块 (联盟链常见)
CONFIRM_DEPTH = 2              # 块确认数
M_OF_N = [(1, 5), (2, 5), (3, 5)]  # 门限 (M, N)
TX_BYTES = 400                 # 注册/撤销事务大小(字节, 估算)
NET_TPS = 2000                 # 底层链吞吐(tx/s, 典型联盟链量级)

# 组合/广播等附加开销系数 (阈值签名组合 + 网络传播)
COMBINE_FACTOR = 0.10          # 组合开销 ≈ 0.1 x sign
NET_OVERHEAD_MS = 5.0          # 单笔链读/写传播延迟(ms, 估算)
READ_MS = 2.0                  # 链上读(状态查询)延迟(ms, 估算)


def t_sign(scheme, M):
    s = SIG[scheme]["sign"]
    return M * s * (1 + COMBINE_FACTOR)


def latency(scheme, M, block_time, op):
    """返回各操作延迟(ms)。"""
    t_s, t_v = SIG[scheme]["sign"], SIG[scheme]["verify"]
    conf = CONFIRM_DEPTH * block_time * 1000      # 确认延迟 ms
    if op == "registration":
        return t_sign(scheme, M) + conf + NET_OVERHEAD_MS
    if op == "revocation":
        return t_s + conf + NET_OVERHEAD_MS
    if op == "discovery":
        return READ_MS + t_v + NET_OVERHEAD_MS
    if op == "handshake":
        return discovery_verify(t_v) + 2 * t_s + 2 * t_v
    if op == "invocation":
        return t_s + t_v
    raise ValueError(op)


def discovery_verify(t_v):
    return READ_MS + t_v + NET_OVERHEAD_MS   # 发现含 1 次验签


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "bir_overhead.csv")
    rows = []
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scheme", "M", "N", "block_time_s", "confirm_depth",
                    "reg_ms", "rev_ms", "disc_ms", "handshake_ms", "invoke_ms",
                    "reg_per_sec"])
        for scheme in SIG:
            for (M, N) in M_OF_N:
                for bt in BLOCK_TIMES:
                    reg = latency(scheme, M, bt, "registration")
                    rev = latency(scheme, M, bt, "revocation")
                    disc = latency(scheme, M, bt, "discovery")
                    hs = latency(scheme, M, bt, "handshake")
                    inv = latency(scheme, M, bt, "invocation")
                    # 注册吞吐: 受确认延迟限制 (1/确认时间) 且不超链容量
                    per_sec = min(1.0 / (reg / 1000), NET_TPS * 0.1)
                    w.writerow([scheme, M, N, bt, CONFIRM_DEPTH,
                                f"{reg:.2f}", f"{rev:.2f}", f"{disc:.2f}",
                                f"{hs:.2f}", f"{inv:.2f}", f"{per_sec:.1f}"])
                    rows.append((scheme, M, bt, reg, rev, disc, hs, inv, per_sec))
    print(f"BIR 开销模型 -> {path}")

    # 摘要 (Ed25519 实测 vs Dilithium 文献, M=2/5, block=2s 基准)
    print("\n=== BIR 开销量化 (基准: M=2/5, 块时间 2s, 确认深度 %d) ===" % CONFIRM_DEPTH)
    print(f"{'scheme':<12}{'reg(ms)':>10}{'rev(ms)':>9}{'disc(ms)':>10}{'handshake(ms)':>15}{'invoke(ms)':>12}{'reg/s':>9}")
    for (scheme, M, bt, reg, rev, disc, hs, inv, pps) in rows:
        if M == 2 and bt == 2:
            print(f"{scheme:<12}{reg:>10.2f}{rev:>9.2f}{disc:>10.2f}{hs:>15.2f}{inv:>12.2f}{pps:>9.1f}")

    # 图
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        schemes = list(SIG.keys())
        m2b2 = [r for r in rows if r[1] == 2 and r[2] == 2]
        ops = ["reg", "rev", "disc", "handshake", "invoke"]
        labels = ["registration", "revocation", "discovery", "handshake", "invocation"]
        x = np.arange(len(ops)); w = 0.25
        fig, ax = plt.subplots(figsize=(10, 4.6))
        for i, scheme in enumerate(schemes):
            d = [r for r in m2b2 if r[0] == scheme][0]
            vals = [d[3], d[4], d[5], d[6], d[7]]
            ax.bar(x + (i - 1) * w, vals, w, label=scheme)
        ax.set_yscale("log")
        ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel("latency (ms, log)"); ax.set_title("BIR operation latency (M=2/5, block=2s)")
        ax.legend(); fig.tight_layout()
        png = os.path.join(args.out, "bir_overhead.png")
        fig.savefig(png, dpi=120); print(f"图表 -> {png}")
    except Exception as e:
        print(f"[skip chart] {e}")


if __name__ == "__main__":
    main()
