"""Bounded-suite runner for three technical reports (the challenge-bound memory sweep,
requirement-preserving human approval and Acceptance Before Export); refuses unexpected
source revisions.

Sources live under --source-root/<repo>. Each one must be either

  * a git checkout whose HEAD equals the pin and whose tracked files are unmodified, or
  * an extracted `git archive` of the pin. Create one with --prepare-from CLONES_ROOT,
    which runs `git archive <pin>` in CLONES_ROOT/<repo> (read only, no checkout or
    branch switch), checks the commit id embedded in the tar and extracts it.

Everything written to --output is free of absolute local paths: commands name the
interpreter as `python`, working directories are relative to the source root, and
logs have the source root, interpreter prefix and home directory replaced by
placeholders.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse, hashlib, importlib.metadata, io, json, os, platform, re, subprocess, sys, tarfile

PINS = {
    'agentrust-telemetry': '29c13cfa4047a0f5784a90df63b22a3568453158',
    'weight-custody-manifest': '2acedfa883204f7d1fd457d3ee603198d85be82c',
    'agent-manifest': '934809709a2815695d65cfacb45dc0a164286046',
}
TASKS = [
    ('telemetry-tests', 'agentrust-telemetry', ['-m', 'unittest', 'discover', '-s', 'tests', '-v']),
    ('telemetry-conformance', 'agentrust-telemetry', ['conformance/runner/validate.py']),
    ('memory-tests', 'weight-custody-manifest/python',
     ['-m', 'pytest', '-p', 'no:cacheprovider', '-o', 'pythonpath=src',
      'tests/test_memory_sweep.py', 'tests/test_kbs.py', '-v']),
    ('approval-tests', 'agent-manifest/python',
     ['-m', 'pytest', '-p', 'no:cacheprovider', '-o', 'pythonpath=src',
      'tests/test_signing.py', 'tests/test_delegation_hitl.py', '-v']),
]
DEPENDENCIES = ['pytest', 'cryptography', 'pydantic', 'jsonschema', 'referencing', 'rfc8785',
                'cbor2', 'agentrust-trace', 'opentelemetry-sdk', 'jcs', 'PyYAML']
MARKER = '.source-commit'


def git(repo, *args, **kw):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo), *args], **kw)


def prepare(clones, root):
    for name, pin in PINS.items():
        dest = root / name
        if dest.exists():
            raise SystemExit(f'{name}: {dest.name} already exists under the source root; use an empty root')
        data = git((clones / name).resolve(), 'archive', '--format=tar', pin)
        commit = subprocess.run(['git', 'get-tar-commit-id'], input=data, capture_output=True, check=True).stdout.decode().strip()
        if commit != pin:
            raise SystemExit(f'{name}: archive carries {commit}, expected {pin}')
        dest.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            tar.extractall(dest, filter='data')
        (dest / MARKER).write_text(pin + '\n', encoding='ascii')


def verify(root):
    method = {}
    for name, pin in PINS.items():
        repo = (root / name).resolve()
        if (repo / MARKER).exists():
            found = (repo / MARKER).read_text(encoding='ascii').strip()
            if found != pin:
                raise SystemExit(f'{name}: archive marker {found}, expected {pin}')
            method[name] = 'git archive of the pinned commit (tar commit id checked)'
            continue
        head = git(repo, 'rev-parse', 'HEAD', text=True).strip()
        if head != pin:
            raise SystemExit(f'{name}: expected {pin}, found {head}')
        if git(repo, 'diff', '--name-only', 'HEAD', text=True).strip():
            raise SystemExit(f'{name}: tracked files differ from the pinned revision')
        method[name] = 'git checkout at the pinned commit, tracked files clean'
    return method


def scrub(text, root):
    subs = [(str(root.resolve()), '<source-root>'), (sys.prefix, '<python-prefix>'),
            (sys.base_prefix, '<python-base>'), (str(Path.home()), '<home>')]
    for old, new in subs:
        for variant in {old, old.replace('\\', '/'), old.replace('\\', '\\\\')}:
            text = text.replace(variant, new)
    return re.sub(r'[A-Za-z]:\\\\?Users\\\\?[^\\\s"\']+', '<home>', text)


def summary(name, text):
    if name == 'telemetry-tests':
        m = re.search(r'Ran (\d+) tests?.*?\n\n(OK.*|FAILED.*)', text, re.S)
        return f'{m.group(1)} tests, {m.group(2).strip()}' if m else 'unparsed'
    if name == 'telemetry-conformance':
        verdicts = [l.split()[0] for l in text.splitlines() if l.startswith(('PASS ', 'FAIL '))]
        return f"{verdicts.count('PASS')} of {len(verdicts)} fixtures returned the expected verdict"
    m = re.findall(r'=+ (.*?) in [0-9.]+s', text)
    return m[-1] if m else 'unparsed'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--prepare-from', type=Path, help='directory of local clones to `git archive` from')
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    if a.prepare_from:
        a.source_root.mkdir(parents=True, exist_ok=True)
        prepare(a.prepare_from, a.source_root)
    method = verify(a.source_root)
    results = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    for name, path, args in TASKS:
        run = subprocess.run([sys.executable, *args], cwd=a.source_root / path, env=env,
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        log = scrub(run.stdout + '\nSTDERR\n' + run.stderr, a.source_root)
        (a.output / (name + '.txt')).write_text(log, encoding='utf-8', newline='\n')
        results.append({'name': name, 'cwd': path, 'command': ['python', *args], 'exit_code': run.returncode,
                        'summary': summary(name, log), 'log': name + '.txt',
                        'log_sha256': hashlib.sha256(log.encode('utf-8')).hexdigest()})
    deps = {}
    for d in DEPENDENCIES:
        try:
            deps[d] = importlib.metadata.version(d)
        except importlib.metadata.PackageNotFoundError:
            deps[d] = None
    record = {'captured_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
              'python': platform.python_version(), 'platform': platform.platform(terse=True),
              'dependencies': deps,
              'sources': {n: {'commit': PINS[n], 'verified_by': method[n]} for n in PINS},
              'results': results,
              'limits': ['Local software tests only; no protected-hardware execution.',
                         'Tests and implementation share a repository and are not independent validation.']}
    (a.output / 'results.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(results, indent=2))
    raise SystemExit(any(r['exit_code'] for r in results))


if __name__ == '__main__':
    main()
