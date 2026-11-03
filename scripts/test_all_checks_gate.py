"""Run #508's exact bash step offline with fixture GitHub responses."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/all-checks.yml"
step = yaml.safe_load(WORKFLOW.read_text())["jobs"]["all-checks"]["steps"][0]
SHA = "a" * 40
good = {
    "id": 1,
    "path": ".github/workflows/ci.yml",
    "head_sha": SHA,
    "status": "completed",
    "conclusion": "success",
    "html_url": "fixture://ci",
}
green = {"name": "Test", "status": "completed", "conclusion": "success"}
ci = 'on:\n  pull_request:\n    paths:\n      - "python/**"\n      - ".github/workflows/*.yml"\n'

STUB = (
    "#!"
    + sys.executable
    + "\n"
    + """import json,os,sys,subprocess
from pathlib import Path
import yaml
s=json.loads(Path(os.environ['SCENARIO']).read_text());args=sys.argv[1:]
if Path(sys.argv[0]).name=='sleep':sys.exit(0)
if Path(sys.argv[0]).name=='yq':
 d=yaml.load(Path(args[-1]).read_text(),Loader=yaml.BaseLoader);on=d.get('on');query=' '.join(args[:-1])
 if 'type' in query:print('!!map' if isinstance(on,dict) else '!!seq')
 elif 'has(' in query:print('true' if isinstance(on,dict) and 'pull_request' in on else 'false')
 else:print(json.dumps(on.get('pull_request') if isinstance(on,dict) else None))
 sys.exit(0)
endpoint=next((a for a in args if a.startswith('repos/')),None)
if '/contents/' in endpoint:print(s['ci']);sys.exit(0)
if s.get('api_error'):sys.exit(1)
if '/files?' in endpoint:data=s['files']
elif '/check-runs?' in endpoint:
 count=Path(os.environ['SCENARIO']+'.count');i=int(count.read_text()) if count.exists() else 0;count.write_text(str(i+1));snap=s['checks'];data={'check_runs':snap[min(i,len(snap)-1)]}
elif '/actions/runs?' in endpoint:data={'workflow_runs':[r for r in s['runs'] if r['head_sha']==os.environ['SHA']]}
else:raise RuntimeError(endpoint)
if '--jq' in args:
 p=subprocess.run(['jq','-r',args[args.index('--jq')+1]],input=json.dumps(data),text=True);sys.exit(p.returncode)
print(json.dumps(data))
"""
)

cases = []


def case(name, expected, **override):
    value = {
        "ci": ci,
        "files": [{"filename": "python/src/change.py"}],
        "checks": [[green]],
        "runs": [good],
    }
    value.update(override)
    cases.append((name, expected, value))


case("applicable-green", 0)
for dependency in ("agt.txt", "agt.in", "agt-overrides.txt", "dev.txt", "release.txt"):
    for expected, runs in ((0, [good]), (1, [])):
        case(
            f"dependency-{dependency}-ci-{'green' if runs else 'missing'}",
            expected,
            ci=(ROOT / ".github/workflows/ci.yml").read_text(),
            files=[{"filename": "requirements/" + dependency}],
            runs=runs,
            deadline="4800",
        )
case("missing-ci", 1, runs=[])
case("stale-sha-only", 1, runs=[dict(good, head_sha="b" * 40)])
for outcome in ("failure", "cancelled", "skipped", "neutral", "timed_out"):
    case("ci-" + outcome, 1, runs=[dict(good, conclusion=outcome)])
case("pending-ci", 1, runs=[dict(good, status="in_progress", conclusion=None)])
case("failed-other-check", 1, checks=[[dict(green, conclusion="failure")]])
case("cancelled-other-check", 1, checks=[[dict(green, conclusion="cancelled")]])
case("pending-other-check", 1, checks=[[dict(green, status="queued", conclusion=None)]])
case(
    "pending-then-success",
    0,
    checks=[[dict(green, status="in_progress", conclusion=None)], [green]],
    deadline="4800",
)
case("no-ci-path-match", 0, files=[{"filename": "README.md"}], runs=[])
case(
    "renamed-from-applicable",
    1,
    files=[{"filename": "README.md", "previous_filename": "python/old.py"}],
    runs=[],
)
case("skipped-other-check", 0, checks=[[dict(green, conclusion="skipped")]])
case("neutral-other-check", 0, checks=[[dict(green, conclusion="neutral")]])
case(
    "policy-gate-separate",
    0,
    checks=[
        [
            green,
            dict(
                green, name="Policy: Awaiting maintainer review", conclusion="failure"
            ),
        ]
    ],
)
case("api-failure", 1, api_error=True)
case(
    "workflow-removes-pr-trigger",
    1,
    ci="on:\n  push:\n    branches: [main]\n",
    files=[{"filename": ".github/workflows/ci.yml"}],
    runs=[],
)

case(
    "workflow-narrows-paths",
    1,
    ci='on:\n  pull_request:\n    paths: ["unrelated/**"]\n',
    files=[{"filename": ".github/workflows/ci.yml"}],
    runs=[],
)
case(
    "workflow-renamed",
    1,
    ci="on:\n  push:\n    branches: [main]\n",
    files=[
        {"filename": "archived.yml", "previous_filename": ".github/workflows/ci.yml"}
    ],
    runs=[],
)

report = []
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    binpath = root / "bin"
    binpath.mkdir()
    for name in ("gh", "yq", "sleep"):
        p = binpath / name
        p.write_text(STUB)
        p.chmod(0o755)
    script = root / "step.sh"
    script.write_text(step["run"])
    for name, expected, scenario in cases:
        p = root / (name + ".json")
        p.write_text(json.dumps(scenario))
        env = dict(
            os.environ,
            PATH=str(binpath) + ":" + os.environ["PATH"],
            SCENARIO=str(p),
            REPO="fixture/repo",
            SHA=SHA,
            PR="1",
            CHANGED="1",
            CI_WORKFLOW=".github/workflows/ci.yml",
            SELF="all-checks",
            GATE="Policy: Awaiting maintainer review",
            GH_TOKEN="offline-fixture",
            CI_APPEAR_LIMIT="0",
            DEADLINE=scenario.get("deadline", "0" if expected else "4800"),
        )
        result = subprocess.run(
            ["bash", str(script)],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        report.append(
            {
                "case": name,
                "expected": expected,
                "actual": result.returncode,
                "output": result.stdout + result.stderr,
            }
        )
        print(name, result.returncode, "expected", expected)
        assert result.returncode == expected, result.stdout + result.stderr
print(
    str(len(report))
    + " offline gate scenarios passed; GitHub responses and sleeps were stubbed"
)
