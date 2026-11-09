#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把官方 backbone (GPT-4o / LLaMA-3-70B) 注册进 models.txt。

★ 必须在【直连外网】的机器上运行 —— 沙箱无直连外网, OpenAI / Together 端点不可达。
★ 运行前先导出密钥 (不要写死到文件):
    export OPENAI_API_KEY="sk-..."
    export TOGETHER_API_KEY="sk-..."        # 或 Groq / Fireworks, 改下方 BASE 即可
★ 幂等: 已存在的 id 不重复添加。

GPT-4o      : OpenAI 官方 API (https://api.openai.com/v1)
LLaMA-3-70B : Together AI 托管 (https://api.together.xyz/v1)
              价值: 这就是 A2ASecBench 论文常用的"官方权重"托管方之一;
              若改用 Groq(llama-3-70b-8192) 或 Fireworks, 仅改 TOGETHER_URL。
"""
import json
import os
import sys

MODELS = "models.txt"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
TOGETHER_URL = "https://api.together.xyz/v1/chat/completions"


def main():
    openai_key = os.environ.get("OPENAI_API_KEY")
    together_key = os.environ.get("TOGETHER_API_KEY")
    if not openai_key and not together_key:
        print("请提供至少一个密钥: export OPENAI_API_KEY=... 或 TOGETHER_API_KEY=...",
              file=sys.stderr)
        sys.exit(2)

    with open(MODELS, encoding="utf-8") as f:
        models = json.load(f)
    ids = {m["id"] for m in models}
    added = []

    if openai_key and "gpt-4o" not in ids:
        models.append({
            "id": "gpt-4o", "name": "gpt-4o", "vendor": "OpenAI",
            "url": OPENAI_URL, "apiKey": openai_key,
            "supportsToolCall": True, "supportsImages": True,
            "supportsReasoning": False, "useCustomProtocol": False,
        })
        added.append("gpt-4o")

    if together_key and "llama-3-70b" not in ids:
        models.append({
            "id": "llama-3-70b", "name": "llama-3-70b", "vendor": "TogetherAI",
            "url": TOGETHER_URL, "apiKey": together_key,
            "supportsToolCall": True, "supportsImages": False,
            "supportsReasoning": False, "useCustomProtocol": False,
        })
        added.append("llama-3-70b")

    with open(MODELS, "w", encoding="utf-8") as f:
        json.dump(models, f, ensure_ascii=False, indent=2)
    print("已写入 models.txt:", added or "(无新增)")


if __name__ == "__main__":
    main()
