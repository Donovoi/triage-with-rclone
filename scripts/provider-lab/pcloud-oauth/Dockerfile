# Disposable positive OAuth feasibility only. Never publish or export this image/cache.
# Built-in BuildKit heredocs; no mutable external Dockerfile frontend.
FROM docker.io/library/python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4
LABEL org.openai.triage.fixture-kind="pcloud-oauth-probe"
ENV LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 HOME=/work TMPDIR=/work
COPY . /opt/fixture/

RUN <<'BUILD'
set -eu
printf '%s\n' 'PCLOUD_BUILD_PHASE=verify'
python3 - <<'PY'
import hashlib, json, pathlib, platform, re, stat
root = pathlib.Path('/opt/fixture')
lock_path = root / 'scripts/provider-lab/pcloud-oauth/build-lock.json'
assert hashlib.sha256(lock_path.read_bytes()).hexdigest() == 'bfd4adee8ecde798aec0ea28e033fe5fd869cc939b57b52ad4524ca60fc67dbd'
lock = json.loads(lock_path.read_bytes())
assert platform.python_version() == lock['python_version'] and platform.machine() == 'x86_64'
expected = {'scripts/provider-lab/pcloud-oauth/' + p for p in ('Dockerfile', 'build-lock.json', 'run_container.py', 'probe.py', 'fixture_oauth.py')}
expected |= {'scripts/provider-lab/fixture_tls.py', 'scripts/provider-lab/fixture_pcloud.py', 'scripts/provider-lab/requirements-fixture.txt', 'rclone-version.env'}
sources = json.loads((root / 'source-manifest.json').read_bytes())
assert set(sources) == expected
actual = set()
for p in root.rglob('*'):
    assert not p.is_symlink()
    if p.is_file():
        assert p.stat().st_nlink == 1
        actual.add(p.relative_to(root).as_posix())
assert actual == expected | {'Dockerfile', 'rclone', 'source-manifest.json'}
for name, sha in sources.items():
    assert re.fullmatch('[a-f0-9]{64}', sha)
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == sha
assert (root / 'Dockerfile').read_bytes() == (root / 'scripts/provider-lab/pcloud-oauth/Dockerfile').read_bytes()
assert sources[lock['requirements']['path']] == lock['requirements']['sha256']
keys = {'RCLONE_VERSION', 'RCLONE_EXE_SHA256', 'RCLONE_WINDOWS_ZIP_SHA256', 'RCLONE_LINUX_ZIP_SHA256', 'RCLONE_LINUX_EXE_SHA256'}
data = (root / 'rclone-version.env').read_bytes()
assert len(data) <= 4096
pins = {}
for line in data.decode('ascii').splitlines():
    if not line or line.startswith('#'):
        continue
    key, sep, value = line.partition('=')
    assert sep and key in keys and key not in pins
    assert re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)' if key == 'RCLONE_VERSION' else '[a-f0-9]{64}', value)
    pins[key] = value
assert set(pins) == keys
assert hashlib.sha256((root / 'rclone').read_bytes()).hexdigest() == pins['RCLONE_LINUX_EXE_SHA256']
PY
printf '%s\n' 'PCLOUD_BUILD_PHASE=dependencies'
# Only hash-locked wheels; the base image supplies the pinned bootstrap pip.
# No pip upgrade, source build, host interpreter or runtime network dependency.
TMPDIR=/tmp python3 -m venv /opt/fixture/venv
TMPDIR=/tmp /opt/fixture/venv/bin/python -m pip --isolated --disable-pip-version-check install --no-cache-dir --require-hashes --only-binary=:all: --index-url https://pypi.org/simple --retries 0 --timeout 20 -r /opt/fixture/scripts/provider-lab/requirements-fixture.txt
/opt/fixture/venv/bin/python -m pip --isolated --disable-pip-version-check check
printf '%s\n' 'PCLOUD_BUILD_PHASE=manifest'
/opt/fixture/venv/bin/python - <<'PY'
import hashlib, importlib.metadata, json, os, pathlib, platform, stat
import cryptography, cffi, pycparser
root = pathlib.Path('/opt/fixture')
lock = json.loads((root / 'scripts/provider-lab/pcloud-oauth/build-lock.json').read_bytes())
expected = lock['requirements']['distributions']
assert {name: importlib.metadata.version(name) for name in expected} == expected
assert cryptography.__version__ == expected['cryptography'] and cffi.__version__ == expected['cffi'] and pycparser.__version__ == '3.00'
assert platform.python_version() == lock['python_version']
assert all(line.split(':', 1)[0] != 'synthetic-oauth' and line.split(':')[2] != '10001' for line in pathlib.Path('/etc/passwd').read_text().splitlines())
assert all(line.split(':', 1)[0] != 'synthetic-oauth' and line.split(':')[2] != '10001' for line in pathlib.Path('/etc/group').read_text().splitlines())
with open('/etc/passwd', 'a') as f:
    f.write('synthetic-oauth:x:10001:10001:Synthetic fixture:/work:/usr/sbin/nologin\n')
with open('/etc/group', 'a') as f:
    f.write('synthetic-oauth:x:10001:\n')
# COPY inherits the host context's private directory modes; make traversal explicit.
for p in (pathlib.Path('/opt'), root, *root.rglob('*')):
    if p.is_dir():
        p.chmod(0o755)
for p in root.rglob('*'):
    if p.is_file() and 'venv' not in p.relative_to(root).parts:
        p.chmod(0o555 if p.name == 'rclone' else 0o444)
work = pathlib.Path('/work')
work.mkdir(exist_ok=True)
work.chmod(0o700)
os.chown(work, 10001, 10001)
PY
BUILD

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/opt/fixture/venv/bin/python"]
CMD ["/opt/fixture/scripts/provider-lab/pcloud-oauth/probe.py", "--rclone", "/opt/fixture/rclone", "--manifest", "/opt/fixture/rclone-version.env"]
