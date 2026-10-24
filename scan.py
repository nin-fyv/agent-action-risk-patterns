"""scan: match agent commands or tool calls against the generic risk patterns in patterns.json.

Input is a text file with one command per line, or a JSON Lines file of tool calls
({"tool_name": ..., "tool_input": {...}}); every string value in a tool call is checked.

Usage:
    python scan.py commands.txt
    python scan.py tool_calls.jsonl --min-severity high
"""
import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).parent
ORDER = {"low": 0, "medium": 1, "high": 2}


def load_patterns(path=HERE / "patterns.json"):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return [(c["id"], c["severity"], c["title"], [re.compile(p, re.I) for p in c["patterns"]]) for c in data["classes"]]


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def items(path):
    for n, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            text = " ".join(_strings(obj)) if isinstance(obj, (dict, list)) else str(obj)
        except json.JSONDecodeError:
            text = line
        yield n, text


def scan(path, classes, min_severity="low"):
    hits = []
    for n, text in items(path):
        for cid, sev, title, pats in classes:
            if ORDER[sev] < ORDER[min_severity]:
                continue
            if any(p.search(text) for p in pats):
                hits.append({"line": n, "class": cid, "severity": sev, "title": title, "text": text[:200]})
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path")
    ap.add_argument("--min-severity", choices=list(ORDER), default="low")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    hits = scan(args.path, load_patterns(), args.min_severity)
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"line {h['line']:>4}  {h['severity']:<6}  {h['class']:<24}  {h['text']}")
        print(f"\n{len(hits)} match(es).")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
