from __future__ import annotations

import os
from pathlib import Path
import shutil
import socketserver
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "infra" / "scripts"


def _script(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


def test_native_environment_exports_one_absolute_artifact_root_with_override() -> None:
    env = _script("native-demo-env.sh")
    assert 'export ARTIFACT_DIR="${ARTIFACT_DIR:-$repo_root/artifacts}"' in env


def test_native_up_sets_api_component_types_and_api_working_directory() -> None:
    native_up = _script("native-up.sh")
    assert 'COMPONENT_TYPE="$component_type"' in native_up
    assert 'start_process api api "$REPO_ROOT/apps/api"' in native_up
    assert 'start_process worker worker "$REPO_ROOT/apps/api"' in native_up
    assert 'start_process scheduler celery_beat "$REPO_ROOT/apps/api"' in native_up
    assert 'cd "$working_dir"' in native_up
    assert '"$REPO_ROOT/infra/scripts/run_migrations.py"' in native_up
    assert "--app-dir" in native_up
    assert "--max-time" in native_up
    assert "/health/ready" in native_up


def test_native_gateway_up_uses_api_working_directory_and_bounded_readiness() -> None:
    gateway_up = _script("native-api-gateway-up.sh")
    assert 'cd "$REPO_ROOT/apps/api"' in gateway_up
    assert "COMPONENT_TYPE=api nohup" in gateway_up
    assert "--connect-timeout" in gateway_up
    assert "--max-time" in gateway_up
    assert "/health/ready" in gateway_up


def test_native_health_keeps_existing_checks_bounded() -> None:
    health = _script("native-health.sh")
    assert "--connect-timeout" in health
    assert "--max-time" in health
    for check in (
        "API direct health",
        "API strict readiness",
        "Web direct route",
        "Gateway API health",
        "Gateway strict readiness",
        "Gateway command center",
    ):
        assert check in health


def _isolated_script(tmp_path: Path, name: str) -> Path:
    scripts = tmp_path / "infra" / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / name
    shutil.copy2(SCRIPTS / name, script)
    (scripts / "native-demo-env.sh").write_text(
        """native_demo_repo_root() { printf '%s\\n' "$MOCK_REPO_ROOT"; }
native_demo_load_env() {
  export NATIVE_LOG_DIR="$MOCK_REPO_ROOT/logs"
  export NATIVE_PID_DIR="$MOCK_REPO_ROOT/pids"
  export NATIVE_POSTGRES_DATA_DIR="$MOCK_REPO_ROOT/postgres-data"
  export NATIVE_POSTGRES_BIN="$MOCK_REPO_ROOT/no-binaries"
  export NATIVE_POSTGRES_HOST=127.0.0.1
  export NATIVE_POSTGRES_PORT=55432
  export NATIVE_POSTGRES_USER=tester
  export NATIVE_POSTGRES_DB=testdb
  export NATIVE_REDIS_DATA_DIR="$MOCK_REPO_ROOT/redis-data"
  export NATIVE_REDIS_BIN="$MOCK_REPO_ROOT/no-binaries"
  export NATIVE_REDIS_HOST=127.0.0.1
  export NATIVE_REDIS_PORT="$MOCK_REDIS_PORT"
  export NATIVE_PYTHON="$MOCK_PYTHON"
}
native_demo_resolve_binary() {
  if [[ "$1" == pg_isready || "$MOCK_RESOLVE_ALL" == 1 ]]; then
    printf '/usr/bin/true\\n'
  else
    return 1
  fi
}
native_demo_print_missing() { echo "Missing $*" >&2; return 1; }
native_demo_port_owner() { echo 'existing pid=1'; }
""",
        encoding="utf-8",
    )
    return script


def _script_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    return {
        **os.environ,
        "MOCK_REPO_ROOT": str(tmp_path),
        "MOCK_PYTHON": sys.executable,
        "MOCK_REDIS_PORT": "1",
        "MOCK_RESOLVE_ALL": "0",
        **overrides,
    }


def test_postgres_preserves_nonempty_directory_without_pg_version(tmp_path: Path) -> None:
    script = _isolated_script(tmp_path, "native-postgres-user.sh")
    data_dir = tmp_path / "postgres-data"
    data_dir.mkdir()
    remnant = data_dir / "base"
    remnant.write_bytes(b"preserve this")

    result = subprocess.run(
        ["bash", str(script)],
        env=_script_env(tmp_path, MOCK_RESOLVE_ALL="1"),
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode != 0
    assert str(data_dir) in result.stderr
    assert "new empty NATIVE_POSTGRES_DATA_DIR" in result.stderr
    assert remnant.read_bytes() == b"preserve this"
    assert list(data_dir.iterdir()) == [remnant]


@pytest.mark.parametrize(
    ("response", "ready"),
    [(b"+PONG\r\n", True), (b"+PONGX\r\n", False)],
)
def test_redis_uses_exact_resp_ping_without_redis_binaries(
    tmp_path: Path, response: bytes, ready: bool
) -> None:
    script = _isolated_script(tmp_path, "native-redis-user.sh")
    requests: list[bytes] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            requests.append(self.request.recv(1024))
            self.request.sendall(response)

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.handle_request, daemon=True)
        worker.start()
        result = subprocess.run(
            ["bash", str(script)],
            env=_script_env(tmp_path, MOCK_REDIS_PORT=str(server.server_address[1])),
            capture_output=True,
            text=True,
            timeout=5,
        )
        worker.join(timeout=2)

    assert requests == [b"*1\r\n$4\r\nPING\r\n"]
    assert (result.returncode == 0) is ready
    if ready:
        assert "already ready" in result.stdout
    else:
        assert "Missing redis-server" in result.stderr


def test_gateway_reports_readiness_503_body_without_retrying(tmp_path: Path) -> None:
    script = _isolated_script(tmp_path, "native-api-gateway-up.sh")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("lsof", "node"):
        binary = fake_bin / name
        binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
    curl = fake_bin / "curl"
    curl.write_text(
        """#!/usr/bin/env bash
while (( $# > 0 )); do
  if [[ "$1" == -o ]]; then body_file="$2"; shift 2; else shift; fi
done
printf '{"database_schema":"pending"}' > "$body_file"
printf '503'
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)

    started = time.monotonic()
    result = subprocess.run(
        ["bash", str(script)],
        env=_script_env(tmp_path, PATH=f"{fake_bin}:{os.environ['PATH']}"),
        capture_output=True,
        text=True,
        timeout=5,
    )
    elapsed = time.monotonic() - started

    assert result.returncode != 0
    assert "API strict readiness (HTTP 503)" in result.stderr
    assert '"database_schema":"pending"' in result.stderr
    assert elapsed < 5
