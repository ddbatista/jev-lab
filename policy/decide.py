#!/usr/bin/env python3
"""Policy gate runner: judge.py decision -> OPA/Rego routing -> decision doc.

The enrich-then-evaluate pattern (no http.send from Rego — it would couple
every eval to judge availability, cache stale verdicts, and turn policy into
an SSRF surface):

  1. judge.py's Judge.decide() runs OUTSIDE OPA (state hygiene + API call +
     fail-closed error capture already live there)
  2. its typed result is passed INTO OPA as input
  3. Rego applies thresholds + overrides + fail-closed defaults
  4. the structured decision doc is printed / appended to JSONL

Usage:
    export TYPESAFE_API_KEY=... ANTHROPIC_API_KEY=...
    python3 policy/decide.py --judge jev --set mini_set.json
    python3 policy/decide.py --judge jev --call '{"tool":"read_file","args":{"path":"/etc/passwd"}}'
    python3 policy/decide.py --offline ...     # replay logged judge rows through policy (no API)

Requires `opa` on PATH (brew install opa on macOS). Stdlib Python only.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

sys.path.insert(0, ROOT)
import judge as judge_mod  # noqa: E402

REGO = os.path.join(HERE, "judge_gate.rego")
DATA = os.path.join(HERE, "data.json")


def find_opa() -> str:
    opa = shutil.which("opa")
    if not opa:
        sys.exit("opa not found on PATH — brew install opa (or grab a release)")
    return opa


def opa_route(opa: str, judge_payload: dict, tool_call: dict) -> dict:
    """Evaluate the policy. OPA failing is itself a fail-closed condition."""
    inp = {"tool_call": {"tool": tool_call.get("tool"),
                         "args": tool_call.get("args", {})},
           "judge": judge_payload}
    cmd = [opa, "eval", "--format", "json",
           "-d", REGO, "-d", DATA,
           "--stdin-input", "data.jevlab.gate.decision"]
    try:
        proc = subprocess.run(cmd, input=json.dumps(inp).encode(),
                              capture_output=True, timeout=10)
    except subprocess.TimeoutExpired:
        return _opa_fail(inp, "opa eval timed out")
    if proc.returncode != 0:
        return _opa_fail(inp, f"opa eval failed: {proc.stderr.decode()[:300]}")
    try:
        out = json.loads(proc.stdout)
        result = out["result"][0]["expressions"][0]["value"]
        if not isinstance(result, dict) or "route" not in result:
            raise ValueError("policy returned no route")
        return result
    except Exception as e:
        return _opa_fail(inp, f"unparseable policy result: {e}")


def _opa_fail(inp: dict, why: str) -> dict:
    """OPA itself unreachable/ill = the policy layer is down: default-deny,
    never a silent allow. Audit doc records the failure category."""
    return {"route": "deny", "allowed": False,
            "reasons": [f"policy_engine_failure:{why}"],
            "policy_version": "unavailable", "provider": inp["judge"].get("provider"),
            "model": inp["judge"].get("model"),
            "confidence": inp["judge"].get("confidence"),
            "checks": inp["judge"].get("checks", {}),
            "abstained": inp["judge"].get("abstained", []),
            "tool": inp["tool_call"].get("tool"),
            "thresholds_applied": None}


def judge_payload(res: dict, provider: str) -> dict:
    """Translate a judge.py decision into the policy's input shape."""
    payload = {
        "provider": provider,
        "available": not res.get("error"),
        "model": res.get("model"),
        "confidence": res.get("confidence"),
        "verdict_probabilities": res.get("raw", {}).get("verdict_probabilities")
        or res.get("raw", {}).get("verdict", {}).get("probabilities"),
        "checks": res.get("checks") or {},
        "abstained": res.get("abstained") or [],
    }
    # only carry the error key when there IS one: policy treats any defined
    # error as judge-unreachable, and `error: null` on success once made
    # every healthy judge read as down (caught by the offline replay)
    if res.get("error"):
        payload["error"] = res["error"]
    return payload


def run(opa, judge, items, log_path, offline_rows=None):
    rows = offline_rows or []
    log = open(log_path, "a")
    for item in items:
        call = {"tool": item["tool"], "args": item["args"],
                "cwd": item.get("cwd", judge_mod.DEFAULT_CWD),
                "role": item.get("role", judge_mod.DEFAULT_ROLE)}
        res = judge.decide(call)
        payload = judge_payload(res, judge.name)
        dec = opa_route(opa, payload, call)
        truth = item.get("count_as") or item.get("truth")
        row = {"ts": _ts(), "item": item["id"], "truth": truth,
               "judge": judge.name, "judge_verdict": res["verdict"],
               **dec}
        log.write(json.dumps(row) + "\n")
        log.flush()
        rows.append(row)
        agree = "" if res["verdict"] == dec["route"] else f"  (policy: {res['verdict']} -> {dec['route']})"
        print(f"item {item['id']:>2}  truth={truth or '-':<8} {dec['route']:<8}"
              f" reasons={sorted(dec['reasons'])}{agree}")
    scored = [r for r in rows if r["truth"] in ("allow", "sandbox", "deny", "gate")]
    ok = sum(1 for r in scored if r["route"] == r["truth"])
    print(f"\npolicy-routed: {ok}/{len(scored)}")
    log.close()
    return rows


def _ts():
    import time
    return time.time()


def replay_last_run(opa, judge_name, log_path, out_log):
    """Offline mode: replay the most recent complete run of judge rows from a
    judge.py JSONL log through the policy — no API calls."""
    rows = [json.loads(l) for l in open(log_path) if l.strip()]
    latest = {}
    for r in rows:
        latest[r["item"]] = r  # last row per item wins
    items = []
    payloads = {}
    for item_id, r in sorted(latest.items()):
        items.append({"id": item_id, "tool": r["state"]["tool"],
                      "args": r["state"]["args"],
                      "truth": r.get("truth")})
        payloads[item_id] = judge_payload(r, judge_name)
    out_rows = []
    log = open(out_log, "a")
    for item in items:
        dec = opa_route(opa, payloads[item["id"]],
                        {"tool": item["tool"], "args": item["args"]})
        truth = item.get("count_as") or item.get("truth")
        row = {"ts": _ts(), "item": item["id"], "truth": truth,
               "judge": judge_name, "judge_verdict": latest[item["id"]]["verdict"],
               **dec}
        log.write(json.dumps(row) + "\n")
        out_rows.append(row)
        print(f"item {item['id']:>2}  truth={truth or '-':<8} {dec['route']:<8}"
              f" reasons={sorted(dec['reasons'])}")
    scored = [r for r in out_rows if r["truth"] in ("allow", "sandbox", "deny", "gate")]
    ok = sum(1 for r in scored if r["route"] == r["truth"])
    print(f"\npolicy-routed (replay): {ok}/{len(scored)}")
    log.close()


def main():
    ap = argparse.ArgumentParser(description="judge -> OPA gate runner")
    ap.add_argument("--judge", choices=("jev", "claude"), default="jev")
    ap.add_argument("--set", dest="set_path", default="test_set_v1.json")
    ap.add_argument("--call", help="single tool call as inline JSON")
    ap.add_argument("--log", default="policy_runs.jsonl",
                    help="output log (bare name resolves against results/)")
    ap.add_argument("--offline", metavar="JUDGE_JSONL",
                    help="replay a logged judge run through policy; no API calls")
    args = ap.parse_args()

    opa = find_opa()
    out_log = (args.log if os.path.sep in args.log
               else os.path.join(ROOT, "results", args.log))
    os.makedirs(os.path.dirname(os.path.abspath(out_log)), exist_ok=True)

    if args.offline:
        replay_last_run(opa, args.judge, args.offline, out_log)
        return
    if args.call:
        judge = judge_mod.make_judge(args.judge)
        call = json.loads(args.call)
        res = judge.decide(call)
        dec = opa_route(opa, judge_payload(res, judge.name), call)
        print(json.dumps(dec, indent=2))
        return
    set_path = (args.set_path if os.path.sep in args.set_path
                else os.path.join(ROOT, "data", args.set_path))
    items = json.load(open(set_path))["items"]
    judge = judge_mod.make_judge(args.judge)
    run(opa, judge, items, out_log)


if __name__ == "__main__":
    main()
