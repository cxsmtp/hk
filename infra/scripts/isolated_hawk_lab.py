#!/usr/bin/env python3
"""Own a disposable, strictly healthy Hawk control plane for local acceptance."""
from __future__ import annotations

import json
import math
import os
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit
from redis.exceptions import ConnectionError as RedisConnectionError


ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "apps" / "api"
PYTHON = Path(sys.executable)
PG_BIN = Path(os.environ.get("HAWK_TEST_PG_BIN") or (str(Path(shutil.which("initdb")).parent) if shutil.which("initdb") else "/Library/PostgreSQL/18/bin"))
REDIS_SERVER = Path(os.environ.get("HAWK_TEST_REDIS_SERVER") or shutil.which("redis-server") or "/tmp/redis-stable/src/redis-server")
FORBIDDEN_PORTS = {3000, 3443, 8000, 55432, 6379, 11434}
REQUIRED_CHECKS = frozenset({
    "database", "migrations", "redis", "celery_worker", "celery_beat",
    "celery_worker_component", "celery_beat_component", "artifact_storage",
})


def validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not (1024 <= port <= 65535) or port in FORBIDDEN_PORTS:
        raise ValueError("shared_or_invalid_lab_port")
    return port


def assigned_loopback_port(excluded: set[int]) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = validate_port(sock.getsockname()[1])
    if port in excluded:
        return assigned_loopback_port(excluded)
    return port


def validate_root(root: Path) -> Path:
    absolute = root.absolute()
    if root.is_symlink() or not absolute.is_dir() or stat.S_IMODE(absolute.stat().st_mode) != 0o700:
        raise ValueError("lab_root_must_be_private_directory")
    if Path("/private/tmp") not in absolute.resolve().parents or ROOT.resolve() in absolute.resolve().parents:
        raise ValueError("lab_root_outside_private_tmp")
    return absolute.resolve()


def validate_owned_path(root: Path, target: Path) -> Path:
    root = validate_root(root)
    resolved = target.resolve()
    if root not in resolved.parents:
        raise ValueError("lab_artifact_outside_owned_root")
    return resolved


def validate_lab_urls(database_url: str, redis_url: str, root: Path, ports: dict[str, int]) -> None:
    if len(set(ports.values())) != len(ports):
        raise ValueError("lab_ports_must_be_distinct")
    for port in ports.values():
        validate_port(port)
    db = urlsplit(database_url)
    redis = urlsplit(redis_url)
    if db.scheme != "postgresql+psycopg2" or db.hostname != "127.0.0.1" or db.port != ports["postgres"] or db.path != "/hawk_lab" or not db.username or not db.password:
        raise ValueError("database_must_be_owned_postgres")
    if redis.scheme != "redis" or redis.hostname != "127.0.0.1" or redis.port != ports["redis"] or not redis.password:
        raise ValueError("redis_must_be_owned_password_instance")
    validate_owned_path(root, root / "artifacts")


def validate_strict_report(report: dict) -> None:
    if report.get("strict_mode") is not True:
        raise RuntimeError("strict_control_plane_mode_off")
    names = report.get("required_checks")
    checks = report.get("checks")
    if not isinstance(names, list) or not REQUIRED_CHECKS.issubset(names) or not isinstance(checks, dict):
        raise RuntimeError("strict_control_plane_checks_missing")
    failed = []
    for name in REQUIRED_CHECKS:
        check = checks.get(name)
        if not isinstance(check, dict):
            failed.append(f"{name}_missing")
        elif check.get("ok") is not True or check.get("status") != "ok":
            status = str(check.get("status") or "unknown")
            status = status if status in {"ok", "unavailable", "out_of_date", "missing", "stale", "incompatible", "skipped", "degraded"} else "other"
            failed.append(f"{name}_{status}")
    if failed or report.get("healthy") is not True:
        raise RuntimeError("strict_control_plane_unhealthy_" + "_".join(sorted(failed or ["inconsistent"])))


def _safe_request(url: str, *, timeout: float = 2.0) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except (ValueError, UnicodeError):
            return exc.code, {}


class IsolatedHawkLab:
    """Start only owned resources; stop them in reverse order on every exit."""

    def __init__(self, root: Path, *, mcp_sessions: bool = False, extra_env: dict[str, str] | None = None):
        self.root = validate_root(root)
        self.mcp_sessions = mcp_sessions
        self.extra_env = extra_env or {}
        self.ports: dict[str, int] = {}
        self.env: dict[str, str] = {}
        self.base_url = ""
        self.processes: dict[str, subprocess.Popen] = {}
        self.logs = []
        self.postgres_started = False
        self.postgres_start_attempted = False
        self.old_cwd: Path | None = None
        self.old_env: dict[str, str] | None = None
        self.prior_sigterm_handler = None
        self.sigterm_installed = False

    def prepare(self) -> None:
        if self.env:
            raise RuntimeError("lab_already_prepared")
        prohibited = {"DATABASE_URL", "REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", "ARTIFACT_DIR", "TEST_PROFILE", "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS", "NATIVE_CONTROL_FRAMEWORK", "TRUSTED_CONTROL_SELECTOR"}
        if prohibited.intersection(self.extra_env):
            raise ValueError("extra_env_may_not_override_lab_isolation_or_controls")
        for binary in (PYTHON, PG_BIN / "initdb", PG_BIN / "pg_ctl", PG_BIN / "createdb", PG_BIN / "pg_isready", REDIS_SERVER):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"lab_binary_missing_{binary.name}")
        self.ports = {}
        for name in ("postgres", "redis", "api"):
            self.ports[name] = assigned_loopback_port(set(self.ports.values()))
        self.base_url = f"http://127.0.0.1:{self.ports['api']}"
        db_password = secrets.token_urlsafe(32)
        redis_password = secrets.token_urlsafe(32)
        db_url = f"postgresql+psycopg2://hawk_lab:{quote(db_password, safe='')}@127.0.0.1:{self.ports['postgres']}/hawk_lab"
        redis_base = f"redis://:{quote(redis_password, safe='')}@127.0.0.1:{self.ports['redis']}"
        validate_lab_urls(db_url, redis_base + "/0", self.root, self.ports)
        for name in ("postgres-data", "postgres-socket", "redis-data", "artifacts", "logs", "cache"):
            (self.root / name).mkdir(mode=0o700)
        # Alembic's repository config uses a relative script_location. Resolve it
        # through a code-reference link while keeping cwd private (no demo .env).
        (self.root / "app").symlink_to(API / "app", target_is_directory=True)
        self._write_private("postgres-password", db_password + "\n")
        self._write_private("redis.conf", "\n".join([
            "bind 127.0.0.1", f"port {self.ports['redis']}", "protected-mode yes",
            f"requirepass {redis_password}", f"dir {self.root / 'redis-data'}",
            "save \"\"", "appendonly no", "daemonize no", "loglevel warning",
        ]) + "\n")
        inherited = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT") if key in os.environ}
        self.env = {
            **inherited,
            "PYTHONPATH": str(API), "PYTHONDONTWRITEBYTECODE": "1", "XDG_CACHE_HOME": str(self.root / "cache"),
            "ENV": "dev", "PILOT_MODE": "false", "DEMO_MODE": "false",
            "SELF_REGISTRATION_ENABLED": "true", "DATABASE_URL": db_url,
            "PGPASSWORD": db_password,
            "REDIS_URL": redis_base + "/0", "CELERY_BROKER_URL": redis_base + "/1",
            "CELERY_RESULT_BACKEND": redis_base + "/2",
            "ARTIFACT_DIR": str(self.root / "artifacts"),
            "SECRET_KEY": secrets.token_urlsafe(48), "SECRET_KEY_LOCK_ENABLED": "true",
            "SECRET_KEY_LOCK_FILE": str(self.root / "secret-key.lock"),
            "SECRET_KEY_LOCK_PEPPER": secrets.token_urlsafe(32),
            "CONNECTOR_SECRETS_KEY": secrets.token_urlsafe(48),
            "CONNECTOR_SECRETS_KDF_SALT": secrets.token_urlsafe(32),
            "ONPREM_BUNDLE_SIGNING_SECRET": secrets.token_urlsafe(48),
            "ENFORCEMENT_PAYLOADS_KEY": secrets.token_urlsafe(48),
            "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS": "true",
            "NATIVE_CONTROL_FRAMEWORK": "true", "TRUSTED_CONTROL_SELECTOR": "true",
            "MCP_PERSISTED_SESSIONS_REQUIRED": "true" if self.mcp_sessions else "false",
            "DEPLOYMENT_ID": "isolated-hawk-lab", "DEPLOYMENT_REGION": "local",
            "DEPLOYMENT_DATA_LOCATION": "local", "DEPLOYMENT_TOPOLOGY": "development",
            "WEB_ORIGIN": self.base_url, "TRUSTED_HOSTS": "127.0.0.1,localhost",
        }
        self.env.update(self.extra_env)
        self.old_cwd = Path.cwd()
        self.old_env = dict(os.environ)
        os.chdir(self.root)  # Pydantic must not load the repository/demo .env file.
        os.environ.clear()
        os.environ.update(self.env)
        if str(API) not in sys.path:
            sys.path.insert(0, str(API))
        if threading.current_thread() is not threading.main_thread():
            self.stop()
            raise RuntimeError("lab_requires_main_thread_for_signal_cleanup")
        self.prior_sigterm_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        self.sigterm_installed = True

    def _handle_sigterm(self, signum, _frame) -> None:
        self.stop()
        raise SystemExit(128 + signum)

    def _write_private(self, name: str, content: str) -> Path:
        path = validate_owned_path(self.root, self.root / name)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
        return path

    def _run(self, command: list[str], label: str, *, timeout: int = 60) -> None:
        with (self.root / "logs" / f"{label}.log").open("wb") as output:
            result = subprocess.run(command, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError(f"lab_{label}_failed")

    def _spawn(self, label: str, command: list[str], *, component: str | None = None) -> None:
        output = (self.root / "logs" / f"{label}.log").open("wb")
        self.logs.append(output)
        env = {**self.env, **({"COMPONENT_TYPE": component} if component else {})}
        self.processes[label] = subprocess.Popen(command, cwd=self.root, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)

    def _wait(self, predicate, label: str, *, seconds: int = 60) -> None:
        deadline = time.monotonic() + seconds
        last_reason = "not_ready"
        while time.monotonic() < deadline:
            if any(process.poll() is not None for process in self.processes.values()):
                raise RuntimeError(f"lab_{label}_process_exited")
            try:
                if predicate():
                    return
            except RedisConnectionError:
                last_reason = "redis_connection_unavailable"
            except (OSError, urllib.error.URLError, ValueError, RuntimeError) as exc:
                last_reason = str(exc).split(":", 1)[0]
            time.sleep(0.25)
        raise RuntimeError(f"lab_{label}_timeout_{last_reason}")

    def _strict_health(self) -> bool:
        from app.db.session import SessionLocal
        from app.services.control_plane_health_service import evaluate_control_plane_health
        with SessionLocal() as db:
            report = evaluate_control_plane_health(db).to_dict()
        validate_strict_report(report)
        status, ready = _safe_request(self.base_url + "/health/ready")
        if status != 200 or ready.get("ready") is not True:
            raise RuntimeError("isolated_api_readiness_failed")
        return True

    def start(self) -> str:
        if not self.env:
            raise RuntimeError("lab_not_prepared")
        try:
            self._run([str(PG_BIN / "initdb"), "-D", str(self.root / "postgres-data"), "--username=hawk_lab", "--auth-host=scram-sha-256", "--auth-local=scram-sha-256", "--pwfile", str(self.root / "postgres-password")], "initdb", timeout=120)
            self.postgres_start_attempted = True
            self._run([str(PG_BIN / "pg_ctl"), "-D", str(self.root / "postgres-data"), "-l", str(self.root / "logs" / "postgres.log"), "-o", f"-h 127.0.0.1 -p {self.ports['postgres']} -k {self.root / 'postgres-socket'}", "-w", "start"], "postgres-start", timeout=60)
            self.postgres_started = True
            self._run([str(PG_BIN / "createdb"), "-h", "127.0.0.1", "-p", str(self.ports["postgres"]), "-U", "hawk_lab", "hawk_lab"], "createdb", timeout=30)
            self._spawn("redis", [str(REDIS_SERVER), str(self.root / "redis.conf")])
            from redis import Redis
            client = Redis.from_url(self.env["REDIS_URL"], socket_connect_timeout=1, socket_timeout=1)
            self._wait(client.ping, "redis", seconds=20)
            self._run([str(PYTHON), str(ROOT / "infra" / "scripts" / "run_migrations.py")], "migrations", timeout=180)
            self._spawn("worker", [str(PYTHON), "-m", "celery", "-A", "app.jobs.celery_app.celery_app", "worker", "--pool=solo", "--concurrency=1", "--loglevel=warning", "-Q", "default,monitoring,auditor,discovery", "--hostname=hawk-isolated@%h"], component="worker")
            self._spawn("beat", [str(PYTHON), "-m", "celery", "-A", "app.jobs.celery_app.celery_app", "beat", "--loglevel=warning", f"--schedule={self.root / 'celerybeat-schedule'}"], component="celery_beat")
            self._spawn("api", [str(PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.ports["api"]), "--log-level", "warning", "--no-access-log"], component="api")
            self._wait(self._strict_health, "strict_readiness", seconds=75)
            return self.base_url
        except BaseException:
            self.stop()
            raise

    def restart_api(self) -> None:
        self._stop_process("api")
        self._spawn("api", [str(PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.ports["api"]), "--log-level", "warning", "--no-access-log"], component="api")
        self._wait(self._strict_health, "api_restart_readiness", seconds=45)

    def _stop_process(self, label: str) -> None:
        process = self.processes.pop(label, None)
        if process is None:
            return
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def stop(self) -> None:
        failed = []
        active = set(self.processes)
        pg_owned = self.postgres_started or (
            self.postgres_start_attempted and (self.root / "postgres-data" / "postmaster.pid").exists()
        )
        try:
            for label in ("api", "beat", "worker", "redis"):
                try:
                    self._stop_process(label)
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    failed.append(label)
            if pg_owned:
                try:
                    self._run([str(PG_BIN / "pg_ctl"), "-D", str(self.root / "postgres-data"), "-m", "immediate", "-w", "stop"], "postgres-stop", timeout=30)
                    self.postgres_started = False
                    self.postgres_start_attempted = False
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    failed.append("postgres")
            else:
                self.postgres_start_attempted = False
            for label in ("api", "redis", "postgres"):
                if label not in active and not (label == "postgres" and pg_owned):
                    continue
                try:
                    self._assert_port_closed(label)
                except (OSError, RuntimeError):
                    failed.append(f"{label}_port")
        finally:
            for output in self.logs:
                try:
                    output.close()
                except OSError:
                    failed.append("log_close")
            self.logs.clear()
            if self.sigterm_installed:
                try:
                    signal.signal(signal.SIGTERM, self.prior_sigterm_handler)
                except (OSError, ValueError):
                    failed.append("signal_restore")
                finally:
                    self.sigterm_installed = False
                    self.prior_sigterm_handler = None
            if self.old_cwd is not None:
                try:
                    os.chdir(self.old_cwd)
                except OSError:
                    failed.append("cwd_restore")
                finally:
                    self.old_cwd = None
            if self.old_env is not None:
                try:
                    os.environ.clear()
                    os.environ.update(self.old_env)
                except OSError:
                    failed.append("env_restore")
                finally:
                    self.old_env = None
        if failed:
            raise RuntimeError("lab_cleanup_failed_" + "_".join(sorted(set(failed))))

    def _assert_port_closed(self, label: str) -> None:
        port = self.ports[label]
        for _ in range(8):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    pass
            except OSError:
                return
            time.sleep(0.25)
        raise RuntimeError(f"lab_{label}_port_still_open")

    def request(self, method: str, path: str, *, headers: dict | None = None, payload: dict | None = None, timeout_seconds: int | float = 30) -> tuple[int, dict]:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 120:
            raise ValueError("invalid_lab_request_timeout")
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            except (ValueError, UnicodeError):
                return exc.code, {}


def self_check() -> int:
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="hawk-strict-lab-", dir="/private/tmp") as name:
            lab = IsolatedHawkLab(Path(name))
            try:
                lab.prepare()
                lab.start()
                print(json.dumps({"status": "strict_ready", "checks": sorted(REQUIRED_CHECKS), "release_ready": False}, sort_keys=True))
                return 0
            finally:
                lab.stop()
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    try:
        raise SystemExit(self_check())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc).split(":", 1)[0], "release_ready": False}, sort_keys=True))
        raise SystemExit(2)
