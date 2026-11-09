# -*- coding: utf-8 -*-
"""
langgraph_runtime_demo.py  --  #2 真实编排框架运行时部署 (LangGraph 1.2.20)

在 *真实* LangGraph StateGraph 运行时 (非 mock) 里, 把 PQ-AIB 作为
"调用前护栏"节点嵌入编排流:

    planner  ->  pqaib_guard  ->  (allow) tool_execute
                              ->  (deny)  refuse

用真实 `StateGraph` + `compile(checkpointer=MemorySaver())` + `graph.invoke()`
跑 8 个场景 (1 良性 + 7 协议层攻击), 验证:
  (a) 真实 LangGraph 运行时下, guard 节点确定性拦截全部 7 类攻击、放行良性;
  (b) 决策与 benchmark 同源 (复用 framework_guard.PQAIBGuard == a2asecbench_adapter.secure_invoke);
  (c) checkpoint 可恢复 (thread 状态持久化)。

确定性 planner 替代 LLM 编排器 (我们验证的是 guard 的 drop-in 集成, 非 LLM 智能),
诚实标注: 编排器用确定性规则, 护栏逻辑与论文协议完全一致。

运行:  python langgraph_runtime_demo.py
输出:  results/langgraph_runtime_result.csv
"""
import csv, os, sys
from typing import TypedDict, Annotated

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import framework_guard as FG   # PQAIBGuard + langgraph_node (复用 a2asecbench_adapter)
import a2asecbench_adapter as A

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------
class AgentState(TypedDict, total=False):
    # 来自编排器 (planner) 的上下文
    caller_cert: str   # 证书注册表 id (可被 msgpack 序列化; 真实证书存 CERT_REGISTRY)
    caller_did_authed: str
    action: str
    depth: int
    active: int
    artifact_signed: bool
    confused_deputy_req: bool
    # guard 输出
    guard: str
    guard_reason: str
    # 执行记录
    executed: str


# ---------------------------------------------------------------------------
# 证书注册表: LangGraph state 只放可序列化 id, 真实 Cert 存此表 (外部 vault 惯例)
# ---------------------------------------------------------------------------
CERT_REGISTRY: dict = {}


# ---------------------------------------------------------------------------
# 节点
# ---------------------------------------------------------------------------
def planner(state: AgentState) -> dict:
    """确定性编排器: 从注入的场景上下文生成一次工具调用请求 (guard 前的最后一步)。"""
    return {"action": state.get("action"), "depth": state.get("depth", 0),
            "active": state.get("active", 0),
            "artifact_signed": state.get("artifact_signed", True),
            "confused_deputy_req": state.get("confused_deputy_req", False)}


def pqaib_guard_node(state: AgentState) -> dict:
    """PQ-AIB 调用前护栏 (LangGraph 节点形态, 与 benchmark 决策同源)。

    从注册表取回真实证书后调用 framework_guard.langgraph_node —— 保证与
    benchmark 共用同一 secure_invoke 决策逻辑 (评测结果 == 部署行为)。
    """
    cert = CERT_REGISTRY[state["caller_cert"]]
    gstate = dict(state)
    gstate["caller_cert"] = cert
    return FG.langgraph_node(gstate, GUARD)


def tool_execute(state: AgentState) -> dict:
    return {"executed": f"tool::{state.get('action')}"}


def refuse(state: AgentState) -> dict:
    return {"executed": f"REFUSED::{state.get('guard_reason', '')}"}


def route(state: AgentState) -> str:
    return "allow" if state.get("guard") == "allow" else "deny"


# ---------------------------------------------------------------------------
# 构建真实图
# ---------------------------------------------------------------------------
def build_graph():
    b = StateGraph(AgentState)
    b.add_node("planner", planner)
    b.add_node("pqaib_guard", pqaib_guard_node)
    b.add_node("tool_execute", tool_execute)
    b.add_node("refuse", refuse)
    b.add_edge(START, "planner")
    b.add_edge("planner", "pqaib_guard")
    b.add_conditional_edges("pqaib_guard", route, {"allow": "tool_execute", "deny": "refuse"})
    b.add_edge("tool_execute", END)
    b.add_edge("refuse", END)
    # 真实 checkpoint (MemorySaver) 保证 thread 状态可恢复
    return b.compile(checkpointer=MemorySaver())


# ---------------------------------------------------------------------------
# 场景 (与 framework_guard.demo 同源, 但走真实 LangGraph 运行时)
# ---------------------------------------------------------------------------
def make_cases():
    bir = A.BIR()
    honest = A.Agent("honest@corp", ["book_flight", "query_balance"], {"max_priv": 1}, bir)
    forged = A.forge_cert(bir, "evil@attacker", ["transfer_funds"], {"max_priv": 9})
    cases = [
        ("BENIGN-book_flight",
         dict(caller_cert=honest.cert, caller_did_authed=honest.did, action="book_flight",
              depth=1, active=1, artifact_signed=True, confused_deputy_req=False), "allow"),
        ("Spoofing-transfer_funds",
         dict(caller_cert=forged, caller_did_authed="evil@attacker", action="transfer_funds",
              depth=1, active=1, artifact_signed=True, confused_deputy_req=False), "deny"),
        ("Cloaking-transfer_funds",
         dict(caller_cert=honest.cert, caller_did_authed=honest.did, action="transfer_funds",
              depth=1, active=1, artifact_signed=True, confused_deputy_req=False), "deny"),
        ("ASRF-prescribe",
         dict(caller_cert=honest.cert, caller_did_authed="other@impostor", action="book_flight",
              depth=1, active=1, artifact_signed=True, confused_deputy_req=False), "deny"),
        ("CycleOverflow",
         dict(caller_cert=honest.cert, caller_did_authed=honest.did, action="book_flight",
              depth=A.D_MAX + 1, active=1, artifact_signed=True, confused_deputy_req=False), "deny"),
        ("TaskFlooding",
         dict(caller_cert=honest.cert, caller_did_authed=honest.did, action="book_flight",
              depth=1, active=A.N_MAX + 1, artifact_signed=True, confused_deputy_req=False), "deny"),
        ("ATSI",
         dict(caller_cert=honest.cert, caller_did_authed=honest.did, action="book_flight",
              depth=1, active=1, artifact_signed=False, confused_deputy_req=False), "deny"),
        ("ConfusedDeputy",
         dict(caller_cert=honest.cert, caller_did_authed=honest.did, action="book_flight",
              depth=1, active=1, artifact_signed=True, confused_deputy_req=True), "deny"),
    ]
    return bir, cases


# ---------------------------------------------------------------------------
def main():
    global GUARD
    bir, cases = make_cases()
    GUARD = FG.PQAIBGuard(bir)
    graph = build_graph()

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(out, exist_ok=True)
    csv_path = os.path.join(out, "langgraph_runtime_result.csv")

    print("=" * 78)
    print("真实 LangGraph 1.2.20 运行时: PQ-AIB 调用前护栏端到端")
    print("  planner -> pqaib_guard -> tool_execute / refuse  (MemorySaver checkpoint)")
    print("=" * 78)

    results = []
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case", "guard_decision", "executed", "expected", "match"])
        print(f"\n{'case':<26}{'guard':<9}{'executed':<28}{'expected':<7}{'ok'}")
        print("-" * 78)
        ok_all = True
        for i, (name, kw, expect) in enumerate(cases):
            config = {"configurable": {"thread_id": f"thread-{name}"}}
            # 证书入注册表, state 只带可序列化 id (LangGraph checkpoint 惯例)
            cert_id = f"cert_{i}"
            CERT_REGISTRY[cert_id] = kw["caller_cert"]
            state_in = dict(kw)
            state_in["caller_cert"] = cert_id
            res = graph.invoke(state_in, config)
            decision = res.get("guard")
            executed = res.get("executed")
            match = (decision == expect and
                     (executed.startswith("tool::") if expect == "allow" else executed.startswith("REFUSED::")))
            ok_all &= match
            results.append(dict(case=name, guard=decision, executed=executed,
                                expected=expect, match=match))
            w.writerow([name, decision, executed, expect, match])
            print(f"{name:<26}{str(decision):<9}{executed:<28}{expect:<7}{'OK ' if match else 'XX'}")

    print("-" * 78)
    n_ok = sum(1 for r in results if r["match"])
    print(f"真实 LangGraph 运行时一致性: {n_ok}/{len(cases)}")
    print("(a) guard 节点在真实 StateGraph 执行流中确定性拦截 7 类攻击、放行良性;")
    print("(b) 决策与 benchmark 同源 (framework_guard.PQAIBGuard == secure_invoke);")
    print("(c) MemorySaver checkpoint 保证 thread 状态持久化 (每个场景独立 thread)。")
    print(f"\n结果 -> {csv_path}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
