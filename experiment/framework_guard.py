# -*- coding: utf-8 -*-
"""
framework_guard.py  --  PQ-AIB 在真实智能体框架中的"可插拔护栏"实现 (填补缺口 #4)

本脚本把《PQ-AIB_tdsc.tex》协议层防御 (BIR 门限签名 AgentCard + ABAC + 进度感知
上限 + 构件来历) 包装成可直接嵌入主流编排框架的"调用前护栏 (pre-tool-call guard)"：

  1) PQAIBGuard            —— 框架无关的护栏核 (复用 a2asecbench_adapter.secure_invoke)
  2) langgraph_node()      —— 以 LangGraph 节点形态嵌入 StateGraph
  3) autogen_tool_guard()  —— 以 AutoGen 工具调用钩子形态嵌入 (GroupChat / Agent)
  4) a2a_task_handler()    —— 以 Google A2A 协议 Task/AgentCard 处理器形态嵌入

设计原则：
  - 与 benchmark (a2asecbench_adapter.py) 共用同一套 `secure_invoke` 决策逻辑与
    同一套签名/策略常量 (D_MAX / N_MAX)，保证"评测结果 == 部署行为"。
  - 纯本地、零网络依赖（仅复用适配器里的密码学/策略部分），可独立 `python framework_guard.py` 跑通。
  - 三个适配器是"drop-in"形态：给出在真实 LangGraph / AutoGen / A2A 工程里替换的位置，
    论文第 §X（运用 / Deployment）可据此说明 PQ-AIB 如何落地。

运行:  python framework_guard.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import a2asecbench_adapter as A   # 复用 BIR / Agent / Cert / forge_cert / secure_invoke / D_MAX / N_MAX


# ----------------------------------------------------------------------------
# 1. 框架无关的护栏核
# ----------------------------------------------------------------------------
class PQAIBGuard:
    """编排器在真正调用工具前必经的一道协议层强制检查。

    调用方身份 (caller_cert) 必须:
      C1 未被撤销 (revoked)
      C2 AgentCard 签名可验 (绑定 did/cap/pol, 抗 Spoofing)
      C3 请求动作在其声明能力内 (ABAC, 抗 Cloaking)
      C4 调用方身份与认证身份一致 (抗 ASRF)
      C5 递归深度 <= D_MAX (抗 CycleOverflow)
      C6 活跃子任务 <= N_MAX (抗 TaskFlooding)
      C7 构件来历可验 (抗 ATSI)
      C8 非越权委托 (抗 ConfusedDeputy)
    任一失败 -> deny (定理 3: 确定性拒绝, 概率 0)。
    """

    def __init__(self, bir: A.BIR):
        self.bir = bir

    def check(self, caller_cert, caller_did_authed, action,
              depth=0, active=0, artifact_signed=True, confused_deputy_req=False):
        decision, reason = A.secure_invoke(
            caller_cert, caller_did_authed, action, depth, active,
            artifact_signed=artifact_signed,
            confused_deputy_req=confused_deputy_req, bir=self.bir)
        return decision, reason


# ----------------------------------------------------------------------------
# 2. LangGraph 适配器 (节点形态)
# ----------------------------------------------------------------------------
def langgraph_node(state: dict, guard: PQAIBGuard) -> dict:
    """LangGraph StateGraph 中的一个 guard 节点。

    在真实工程中：
        from langgraph.graph import StateGraph
        builder = StateGraph(AgentState)
        builder.add_node("pqaib_guard", lambda s: langgraph_node(s, guard))
        builder.add_edge("planner", "pqaib_guard")
        builder.add_conditional_edges("pqaib_guard",
            lambda s: "tool" if s["guard"]=="allow" else "refuse")
    编排器(planner)生成的 tool_call 在进入工具执行前先过本节点。
    """
    decision, reason = guard.check(
        state["caller_cert"], state.get("caller_did_authed"),
        state["action"], depth=state.get("depth", 0),
        active=state.get("active", 0),
        artifact_signed=state.get("artifact_signed", True),
        confused_deputy_req=state.get("confused_deputy_req", False))
    return {"guard": decision, "guard_reason": reason}


# ----------------------------------------------------------------------------
# 3. AutoGen 适配器 (工具调用钩子形态)
# ----------------------------------------------------------------------------
def autogen_tool_guard(caller_cert, caller_did_authed, action,
                       guard: PQAIBGuard, ctx=None) -> tuple:
    """AutoGen 中包装工具函数的守卫。

    在真实工程中：
        def safe_tool(agent, *args, **kwargs):
            decision, reason = autogen_tool_guard(
                agent.capability_cert, agent.authed_did, kwargs["action"], guard)
            if decision != "allow":
                return f"[PQ-AIB BLOCKED] {reason}"
            return real_tool(*args, **kwargs)
        # 把 safe_tool 注册为 Agent 的可调用函数, 替代裸 tool
    """
    return guard.check(caller_cert, caller_did_authed, action,
                       depth=(ctx or {}).get("depth", 0),
                       active=(ctx or {}).get("active", 0),
                       artifact_signed=(ctx or {}).get("artifact_signed", True),
                       confused_deputy_req=(ctx or {}).get("confused_deputy_req", False))


# ----------------------------------------------------------------------------
# 4. Google A2A 协议适配器 (Task / AgentCard 处理器形态)
# ----------------------------------------------------------------------------
def a2a_task_handler(task: dict, peer_cert: A.Cert, guard: PQAIBGuard) -> dict:
    """A2A 服务端处理 incoming Task 前的护栏。

    A2A v1.0 (2026) 引入"签名 AgentCard"(JWS), 但签名仅为 'MAY', 默认不强执。
    PQ-AIB 把该签名上升到 *强制* 验签 + 能力/进度/委托策略强制:
      - task["agentCard"] 即为 peer_cert (由 BIR 门限签发的可验证 AgentCard)
      - task["skill"]     即请求能力 (action)
      - task["contextId"] 递归深度 / task 活跃数 由编排器维护
    在真实工程中作为 A2A TaskHandler 的前置中间件 (见 §X Deployment)。
    """
    # 发现阶段: 验签 + 未撤销 (对应 A2A 签名 AgentCard 强制校验)
    if not A.discover(guard.bir, peer_cert):
        return {"decision": "deny", "reason": "A2A: AgentCard signature invalid / revoked"}
    decision, reason = guard.check(
        peer_cert, task.get("caller_did_authed"), task["skill"],
        depth=task.get("depth", 0), active=task.get("active", 0),
        artifact_signed=task.get("artifact_signed", True),
        confused_deputy_req=task.get("confused_deputy_req", False))
    return {"decision": decision, "reason": reason}


# ----------------------------------------------------------------------------
# 5. 可运行演示: 编排器在护栏下处理 7 类攻击 + 良性
# ----------------------------------------------------------------------------
def demo():
    print("=" * 74)
    print("PQ-AIB Framework Guard — 在编排框架中以'调用前护栏'形态拦截协议层攻击")
    print("=" * 74)
    bir = A.BIR()
    guard = PQAIBGuard(bir)

    # 注册两个合法 agent (带正确 BIR 门限签名 AgentCard)
    honest = A.Agent("honest@corp", ["book_flight", "query_balance"], {"max_priv": 1}, bir)
    planner = A.Agent("planner@corp", ["delegate"], {"max_priv": 2}, bir)

    # 构造 7 类攻击 + 1 良性 的调用上下文
    cases = []

    # 良性: honest 调用 book_flight, 深度/并发合法
    cases.append(("BENIGN-book_flight",
                  dict(caller_cert=honest.cert, caller_did_authed=honest.did,
                       action="book_flight", depth=1, active=1,
                       artifact_signed=True, confused_deputy_req=False), "allow"))

    # Spoofing: 攻击者伪造 AgentCard (用自己密钥签, 但 pk_bir 指回 BIR) -> 验签失败
    forged = A.forge_cert(bir, "evil@attacker", ["transfer_funds"], {"max_priv": 9})
    cases.append(("Spoofing-transfer_funds",
                  dict(caller_cert=forged, caller_did_authed="evil@attacker",
                       action="transfer_funds", depth=1, active=1), "deny"))

    # Cloaking: 合法身份但请求未声明的能力
    cases.append(("Cloaking-transfer_funds",
                  dict(caller_cert=honest.cert, caller_did_authed=honest.did,
                       action="transfer_funds", depth=1, active=1), "deny"))

    # ASRF: 调用方认证身份 != AgentCard.did
    cases.append(("ASRF-prescribe",
                  dict(caller_cert=honest.cert, caller_did_authed="other@impostor",
                       action="book_flight", depth=1, active=1), "deny"))

    # CycleOverflow: 递归深度超 D_MAX
    cases.append(("CycleOverflow",
                  dict(caller_cert=honest.cert, caller_did_authed=honest.did,
                       action="book_flight", depth=A.D_MAX + 1, active=1), "deny"))

    # TaskFlooding: 活跃子任务超 N_MAX
    cases.append(("TaskFlooding",
                  dict(caller_cert=honest.cert, caller_did_authed=honest.did,
                       action="book_flight", depth=1, active=A.N_MAX + 1), "deny"))

    # ATSI: 构件来历不可验
    cases.append(("ATSI",
                  dict(caller_cert=honest.cert, caller_did_authed=honest.did,
                       action="book_flight", depth=1, active=1,
                       artifact_signed=False), "deny"))

    # ConfusedDeputy: 低特权 agent 请求越权委托
    cases.append(("ConfusedDeputy",
                  dict(caller_cert=honest.cert, caller_did_authed=honest.did,
                       action="delegate", depth=1, active=1,
                       confused_deputy_req=True), "deny"))

    # ---- 逐框架形态演示 ----
    print(f"\n{'case':<26}{'LangGraph':<12}{'AutoGen':<12}{'A2A':<10}{'期望'}")
    print("-" * 74)
    ok = 0
    for name, kw, expect in cases:
        # LangGraph 节点
        lg = langgraph_node({"caller_cert": kw["caller_cert"],
                             "caller_did_authed": kw.get("caller_did_authed"),
                             "action": kw["action"], "depth": kw.get("depth", 0),
                             "active": kw.get("active", 0),
                             "artifact_signed": kw.get("artifact_signed", True),
                             "confused_deputy_req": kw.get("confused_deputy_req", False)}, guard)
        # AutoGen 钩子
        ag = autogen_tool_guard(kw["caller_cert"], kw.get("caller_did_authed"),
                                kw["action"], guard,
                                ctx={"depth": kw.get("depth", 0), "active": kw.get("active", 0),
                                     "artifact_signed": kw.get("artifact_signed", True),
                                     "confused_deputy_req": kw.get("confused_deputy_req", False)})
        # A2A 处理器 (用 planner 作为委托方演示 ConfusedDeputy 的 A2A 形态)
        a2a_task = {"agentCard": kw["caller_cert"], "caller_did_authed": kw.get("caller_did_authed"),
                    "skill": kw["action"], "depth": kw.get("depth", 0), "active": kw.get("active", 0),
                    "artifact_signed": kw.get("artifact_signed", True),
                    "confused_deputy_req": kw.get("confused_deputy_req", False)}
        a2a = a2a_task_handler(a2a_task, kw["caller_cert"], guard)

        lg_d = lg["guard"]; ag_d = ag[0]; a2a_d = a2a["decision"]
        match = (lg_d == expect and ag_d == expect and a2a_d == expect)
        ok += 1 if match else 0
        print(f"{name:<26}{lg_d:<12}{ag_d:<12}{a2a_d:<10}{expect}{'  ✓' if match else '  ✗'}")

    print("-" * 74)
    print(f"护栏一致性: {ok}/{len(cases)} 个场景在三种框架形态下判定一致且符合预期。")
    print("结论: PQ-AIB 作为'调用前护栏'在 LangGraph / AutoGen / A2A 三种形态下")
    print("      均确定性拦截 7 类协议层攻击, 放行良性 —— 与 benchmark 决策逻辑同源。")
    return ok == len(cases)


if __name__ == "__main__":
    success = demo()
    sys.exit(0 if success else 1)
