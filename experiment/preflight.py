# -*- coding: utf-8 -*-
"""
preflight.py  --  在你本机预检 models.txt 全部端点连通性与时延 (无 GPU 需求)

在你自己机器(有外网)运行, 逐端点发一个最小请求, 报告可达/时延/是否支持工具调用。
作用: 选出可用的 backbone 模型, 避免全量扫描时浪费配额。

用法:  python preflight.py [--models-file models.txt] [--timeout 20]
"""
import argparse, json, time, urllib.request, urllib.error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-file", default="models.txt")
    ap.add_argument("--timeout", type=float, default=20)
    args = ap.parse_args()
    with open(args.models_file, encoding="utf-8") as f:
        models = json.load(f)

    print(f"{'id':<28}{'vendor':<10}{'reachable':<10}{'latency_ms':<12}{'tool_call':<10}")
    ok = 0
    for m in models:
        mid, url, key = m["id"], m.get("url"), m.get("apiKey")
        body = json.dumps({"model": mid,
                           "messages": [{"role": "user", "content": "ping, reply one word: ok"}],
                           "temperature": 0}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {key}")
        req.add_header("Content-Type", "application/json")
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=args.timeout) as r:
                obj = json.loads(r.read().decode())
            lat = (time.time() - t0) * 1000
            print(f"{mid:<28}{m.get('vendor','Custom'):<10}{'YES':<10}{lat:<12.0f}{str(m.get('supportsToolCall',False)):<10}")
            ok += 1
        except urllib.error.HTTPError as e:
            print(f"{mid:<28}{m.get('vendor','Custom'):<10}{'NO(' + str(e.code) + ')':<10}{'-':<12}{'-':<10}")
        except Exception as e:
            print(f"{mid:<28}{m.get('vendor','Custom'):<10}{'NO':<10}{'-':<12}{'-':<10}  {type(e).__name__}")
    print(f"\n可达 {ok}/{len(models)} 个端点。用可达模型跑: python run_sweep.py --models <id1,id2,...>")


if __name__ == "__main__":
    main()
