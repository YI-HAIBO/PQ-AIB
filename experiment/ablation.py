# -*- coding: utf-8 -*-
"""
ablation.py  --  PQ-AIB 组件消融实验 (证明"每组件不可省", Q1 门槛6)

复用 a2asecbench_adapter 的 PQ-AIB 原语(BIR/Agent/forge_cert/secure_invoke 等),
通过组件开关逐步关闭 PQ(签名)/Blockchain(BIR注册撤销)/Identity(身份绑定)/
Progress(进度感知)/ABAC(能力与特权)/Provenance(构件来历), 观察各攻击 ASR 变化:
  完整 PQ-AIB(全部开启)          -> 七类 ASR = 0
  关闭"负责该攻击的组件"        -> 该攻击 ASR 回升 (证明该组件不可省)
  基线(全部关闭)                 -> 七类 ASR 回升

攻击 -> 负责组件映射:
  Spoofing->pq, Cloaking->abac, CycleOverflow->progress, TaskFlooding->progress,
  ASRF->identity, ATSI->provenance, ConfusedDeputy->abac

运行: python ablation.py [--n 200] [--out results]
"""
import argparse, os, csv, time
import a2asecbench_adapter as A

# 完整组件集与"攻击->负责组件"映射
COMPONENTS = ["pq", "blockchain", "identity", "progress", "abac", "provenance"]
# 本地攻击集: adapter 七类 + Revoked(已撤销身份, 检验 blockchain 撤销组件)
ATTACKS_L = A.ATTACKS + ["Revoked"]
ATTACK_GATE = {"Spoofing": "pq", "Cloaking": "abac", "CycleOverflow": "progress",
               "TaskFlooding": "progress", "ASRF": "identity", "ATSI": "provenance",
               "ConfusedDeputy": "abac", "Revoked": "blockchain"}


def make_cfg(**over):
    cfg = {c: True for c in COMPONENTS}
    cfg.update(over)
    return cfg


def gate(cfg, cert, did, action, depth, active, art, conf, bir):
    """按组件开关执行网关检查 (对应 a2asecbench_adapter.secure_invoke 的分项)。"""
    if cfg["blockchain"] and bir is not None and bir.is_revoked(cert.did):
        return ("deny", "revoked")
    if cfg["pq"] and not cert.verify():
        return ("deny", "Spoofing: invalid cert signature")
    if cfg["abac"] and action not in cert.cap:
        return ("deny", "Cloaking: capability not in AgentCard")
    if cfg["identity"] and (did is None or did != cert.did):
        return ("deny", "ASRF: unauthenticated caller identity")
    if cfg["progress"] and depth > A.D_MAX:
        return ("deny", "CycleOverflow: depth exceeds D_MAX")
    if cfg["progress"] and active > A.N_MAX:
        return ("deny", "TaskFlooding: active exceeds N_MAX")
    if cfg["provenance"] and not art:
        return ("deny", "ATSI: artifact provenance unverifiable")
    if cfg["abac"] and conf and cert.pol.get("max_priv", 1) < 2:
        return ("deny", "ConfusedDeputy: privilege escalation blocked")
    return ("allow", "ok")


def build_scenario(atk, bir, domain="finance"):
    """构造攻击场景 -> 返回传给 gate 的 (cert, did, action, depth, active, art, conf)。
    与 a2asecbench_adapter.run_pqaib 的构造语义一致。"""
    hr = A.HIGH_RISK[domain]
    if atk == "Spoofing":
        cert = A.forge_cert(bir, "admin", [hr], {"max_priv": 2})
        return cert, "admin", hr, 1, 1, True, False
    if atk == "Cloaking":
        agent = A.Agent("att-c", ["query_balance"], {"max_priv": 1}, bir)
        return agent.cert, agent.did, hr, 1, 1, True, False
    if atk == "ASRF":
        agent = A.Agent("att-r", [hr], {"max_priv": 1}, bir)
        return agent.cert, "victim-other-did", hr, 1, 1, True, False
    if atk == "CycleOverflow":
        agent = A.Agent("att-o", [hr], {"max_priv": 1}, bir)
        return agent.cert, agent.did, hr, A.D_MAX + 2, 1, True, False
    if atk == "TaskFlooding":
        agent = A.Agent("att-f", [hr], {"max_priv": 1}, bir)
        return agent.cert, agent.did, hr, 1, A.N_MAX + 3, True, False
    if atk == "ATSI":
        agent = A.Agent("att-s", [hr], {"max_priv": 1}, bir)
        return agent.cert, agent.did, hr, 1, 1, False, False
    if atk == "ConfusedDeputy":
        agent = A.Agent("att-d", [hr], {"max_priv": 1}, bir)
        return agent.cert, agent.did, hr, 1, 1, True, True
    if atk == "Revoked":
        # 已注册但随后被 BIR 撤销的身份 (如密钥泄露被撤销) 试图调用
        agent = A.Agent("leaked-agent", [hr], {"max_priv": 1}, bir)
        bir.revoked.add(agent.did)
        return agent.cert, agent.did, hr, 1, 1, True, False
    raise ValueError(atk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200, help="每配置每攻击重复次数")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    bir = A.BIR()
    cfgs = {
        "full":      make_cfg(),
        "w/o PQ":    make_cfg(pq=False),
        "w/o Blockchain": make_cfg(blockchain=False),
        "w/o Identity":   make_cfg(identity=False),
        "w/o Progress":   make_cfg(progress=False),
        "w/o ABAC":       make_cfg(abac=False),
        "w/o Provenance": make_cfg(provenance=False),
        "baseline": make_cfg(**{c: False for c in COMPONENTS}),
    }

    res = {}   # cfg -> attack -> [success, total]
    for name in cfgs:
        res[name] = {a: [0, 0] for a in ATTACKS_L}
    for cfg_name, cfg in cfgs.items():
        for atk in ATTACKS_L:
            succ = 0
            for _ in range(args.n):
                cert, did, action, depth, active, art, conf = build_scenario(atk, bir)
                d, _ = gate(cfg, cert, did, action, depth, active, art, conf, bir)
                if d == "allow":
                    succ += 1
            res[cfg_name][atk] = [succ, args.n]

    # 输出 CSV
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "ablation_asr.csv")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "attack", "success", "total", "asr"])
        for cfg_name in cfgs:
            for atk in ATTACKS_L:
                s, t = res[cfg_name][atk]
                w.writerow([cfg_name, atk, s, t, f"{s/t:.4f}"])
    print(f"消融结果 -> {path}")

    # 摘要打印
    print("\n=== PQ-AIB 组件消融 (每组件 ASR, n=%d) ===" % args.n)
    print(f"{'config':<16}" + "".join(f"{a[:9]:>11}" for a in ATTACKS_L))
    for cfg_name in cfgs:
        line = f"{cfg_name:<16}"
        for atk in ATTACKS_L:
            s, t = res[cfg_name][atk]
            line += f"{s/t:>11.3f}"
        print(line)
    print("\n解读: 完整 PQ-AIB 全为 0.000; 关闭'负责组件'对应攻击回升 -> 该组件不可省。")

    # 柱状图
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        cfg_names = list(cfgs.keys())
        atks = ATTACKS_L
        x = np.arange(len(cfg_names)); w = 0.11
        fig, ax = plt.subplots(figsize=(13, 5))
        for i, atk in enumerate(atks):
            vals = [res[c][atk][0] / res[c][atk][1] for c in cfg_names]
            ax.bar(x + (i - 3.5) * w, vals, w, label=atk)
        ax.set_xticks(x); ax.set_xticklabels(cfg_names, rotation=25, ha="right", fontsize=8)
        ax.set_ylabel("ASR"); ax.set_ylim(0, 1.05)
        ax.set_title("PQ-AIB component ablation — ASR by configuration")
        ax.legend(fontsize=7, ncol=4); fig.tight_layout()
        png = os.path.join(args.out, "ablation_asr.png")
        fig.savefig(png, dpi=120); print(f"图表 -> {png}")
    except Exception as e:
        print(f"[skip chart] {e}")


if __name__ == "__main__":
    main()
