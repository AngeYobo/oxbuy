# Phase 2C documentation cross-check (read-only). Run from the repository root:
#   python3 -I evidence/phase-2c/final/verify-docs.py
# Prints one line per check and "RESULT: PASS|FAIL".
import json, os, re, sys

E = "evidence/phase-2c"
fails = []

def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")
    if not ok:
        fails.append(name)

def tap_summary(path):
    t = open(path).read()
    g = lambda k: int(re.search(rf"^# {k} (\d+)", t, re.M).group(1))
    return {k: g(k) for k in ("tests", "pass", "fail", "cancelled", "skipped", "todo")}, t

# 1. Final validation numbers.
s, t = tap_summary(f"{E}/fi07b-remediation/full-suite.tap")
check("final suite 184/184", s == {"tests": 184, "pass": 184, "fail": 0, "cancelled": 0, "skipped": 0, "todo": 0}, str(s))
groups = {"AN": r"AN\d", "RS": r"RS\d", "OR": r"OR\d", "ID": r"ID\d", "CX1": r"CX1", "CX2": r"CX2", "FI": r"FI-"}
counts = {k: len(re.findall(rf"^ok \d+ - {v}", t, re.M)) for k, v in groups.items()}
check("Phase 2C groups 10/7/5/4/8/6/13 = 53", counts == {"AN": 10, "RS": 7, "OR": 5, "ID": 4, "CX1": 8, "CX2": 6, "FI": 13}, str(counts))
codes = open(f"{E}/fi07b-remediation/exit-codes.txt").read()
check("FI-07b alone x3, typecheck, suite exit 0", all(f"{k} exit=0" in codes for k in ("fi07b-alone-run1", "fi07b-alone-run2", "fi07b-alone-run3", "typecheck", "full-suite")), codes.replace("\n", "; "))
for i in (1, 2, 3):
    a, _ = tap_summary(f"{E}/fi07b-remediation/fi07b-alone-run{i}.tap")
    check(f"FI-07b alone run {i} 1/1", a["tests"] == 1 and a["pass"] == 1, str(a))

# 2. Superseded runs are what the docs say.
for f in ("final/run1-test-results.tap", "final/test-results.tap"):
    a, at = tap_summary(f"{E}/{f}")
    bad = re.findall(r"^not ok \d+ - (\S+)", at, re.M)
    check(f"superseded {f} 183/184, FI-07b failed", a["tests"] == 184 and a["pass"] == 183 and bad == ["FI-07b"], f"{a} {bad}")
a, _ = tap_summary(f"{E}/an4-fixture-reverify/full-suite.tap")
check("an4-fixture-reverify 171/171", a["tests"] == 171 and a["pass"] == 171, str(a))

# 3. Mutation verdicts.
final = {}
for run in (1, 2, 3):
    for r in json.load(open(f"{E}/mutation/results-run{run}.json")):
        if r["id"] != "BASELINE":
            final[r["id"]] = (run, r["verdict"], r.get("failing", []))
        else:
            check(f"mutation run {run} baseline PASS", r["verdict"] == "PASS", f"{r.get('tests')} tests")
check("M01-M13 present", sorted(final) == [f"M{i:02d}" for i in range(1, 14)], str(sorted(final)))
check("M01-M13 all KILLED (latest run)", all(v[1] == "KILLED" for v in final.values()), str({k: v[:2] for k, v in final.items() if v[1] != "KILLED"}))
check("M07 killed in run 3, 4 failing", final["M07"][0] == 3 and len(final["M07"][2]) == 4)
check("M13 killed in run 2, 4 failing", final["M13"][0] == 2 and len(final["M13"][2]) == 4)
r1 = {r["id"]: r for r in json.load(open(f"{E}/mutation/results-run1.json"))}
check("history: M07 run1 SURVIVED w/ 4 not-ok, M13 run1 SURVIVED", r1["M07"]["verdict"] == "SURVIVED" and len(r1["M07"]["failing"]) == 4 and r1["M13"]["verdict"] == "SURVIVED")

# 4. Demo results.
d = [json.load(open(f"{E}/demo/demo-run{i}.json")) for i in (1, 2, 3)]
dec = lambda x: x["agent"]["weather"].get("result", {}).get("decision") or x["agent"]["weather"].get("decision")
check("demo ALLOW, ALLOW, DENY", [dec(x) for x in d] == ["ALLOW", "ALLOW", "DENY"])
check("demo run3 BUDGET_EXCEEDED", d[2]["agent"]["weather"].get("reasons") == ["BUDGET_EXCEEDED"])
check("demo ledger 1,2,2", [x["ledger_payments"] for x in d] == [1, 2, 2])
check("demo charge 10000,20000,20000", [list(x["policy_state"]["spent_in_period"].values())[0] for x in d] == ["10000", "20000", "20000"])
check("demo unlisted ALLOWLIST_TARGET, EACCES x2", all(x["agent"]["unlisted"].get("reasons") == ["ALLOWLIST_TARGET"] and x["agent"]["executor_socket_connect"] == "EACCES" and x["agent"]["wallet_key_read"] == "EACCES" for x in d))
v = json.load(open(f"{E}/demo/policy-verify-after-run3.json"))
check("verify: version 4, matches, append-only", v["version"] == 4 and v["matches"] and v["append_only"])
check("BLOCKED case", json.load(open(f"{E}/demo/demo-blocked-no-executor-state.json"))["status"] == "BLOCKED")

# 5. Every evidence path cited in the Phase 2C docs exists.
conf = open("docs/CONFORMANCE.md").read()
sec = conf[conf.index("## Phase 2C: financial integrity"):conf.index("## AGENTS.md validation list")]
texts = {"CONFORMANCE Phase 2C": sec}
for f in ("MANIFEST.md", "RECOVERY.md", "mutation/README.md", "demo/README.md", "fi07b-remediation/README.md", "an4-fixture-reverify/README.md", "adversarial/README.md"):
    texts[f] = open(f"{E}/{f}").read()
missing = []
# Bare file names are cited relative to the directory under discussion: accept a match anywhere under E.
present = {f for _, _, fs in os.walk(E) for f in fs}
# Runtime file names mentioned in prose (state/journal layout), not evidence citations.
RUNTIME = {"state.json", "JOURNAL.json", "journal.log", "decisions.jsonl", "ledger.jsonl"}
for name, txt in texts.items():
    for p in set(re.findall(r"`((?:evidence/phase-2c/)?[\w./{},-]+\.(?:tap|txt|json|log|md|diff|ts))`", txt)):
        for q in re.sub(r"\{([^}]*)\}", lambda m: "|".join(m.group(1).split(",")), p).split("|") if "{" in p else [p]:
            pass
        cands = []
        m = re.match(r"(.*)\{([^}]*)\}(.*)", p)
        cands = [m.group(1) + x + m.group(3) for x in m.group(2).split(",")] if m else [p]
        for c in cands:
            if c.startswith(("src/", "tests/", "docs/", "dist/", "node_modules/")) or "/" not in c and not c.endswith((".tap", ".json", ".log", ".diff")):
                continue
            here = os.path.dirname(f"{E}/{name}") if name != "CONFORMANCE Phase 2C" else E
            opts = [c, f"{E}/{c}", os.path.join(here, c)]
            if c in RUNTIME or ("/" not in c and c in present):
                continue
            if not any(os.path.exists(o) for o in opts):
                missing.append(f"{name}: {c}")
check("cited evidence paths exist", not missing, "; ".join(sorted(set(missing))))

# 6. No forbidden claims.
for name, txt in texts.items():
    bad = [w for w in ("production ready", "production-ready", "audit approved", "independently approved") if w in txt.lower()]
    check(f"no readiness/approval claim in {name}", not bad, str(bad))

print("RESULT:", "PASS" if not fails else f"FAIL ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
