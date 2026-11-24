"""Run the API integration suite against explicitly disposable PostgreSQL/Redis.

This owns its test API/worker/beat processes; it never stops an existing service.
Use fresh containers/databases. Existing public tables or acceptance DBs are refused.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import urlopen
import xml.etree.ElementTree as ET

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "apps/api"
DATABASE = "hawk_collaboration_test"
ACCEPTANCE_DATABASE = "aicontrol_phase5_acceptance"


def checked_targets() -> tuple[str, str]:
    if (API / ".env").exists():
        raise ValueError("Run in a clean test checkout without a local .env")
    if os.environ.get("HAWK_DISPOSABLE_TEST_ENV") != "1":
        raise ValueError("HAWK_DISPOSABLE_TEST_ENV=1 must explicitly identify disposable services")
    database_url = os.environ.get("DATABASE_URL", "")
    redis_url = os.environ.get("REDIS_URL", "")
    db = make_url(database_url)
    redis = urlsplit(redis_url)
    if db.get_backend_name() != "postgresql" or db.database != DATABASE:
        raise ValueError(f"DATABASE_URL must target the disposable {DATABASE} database")
    if db.host not in {"127.0.0.1", "localhost", "db"}:
        raise ValueError("Database must be a local or isolated Compose service")
    if redis.scheme != "redis" or redis.hostname not in {"127.0.0.1", "localhost", "redis"}:
        raise ValueError("Redis must be a local or isolated Compose service")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        if db.host != "db" and (db.port or 5432) in {5432, 55432}:
            raise ValueError("Use an isolated PostgreSQL test port, not a native service port")
        if redis.hostname != "redis" and (redis.port or 6379) == 6379:
            raise ValueError("Use an isolated Redis test port, not the native service port")
    return database_url, redis_url


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--web", action="store_true", help="Build/test/start the local web console")
    parser.add_argument("--browser-smoke", action="store_true", help="Verify synthetic browser login and eight routes")
    parser.add_argument("--browser-executable", type=Path)
    parser.add_argument("--serve", action="store_true", help="Keep owned services running after acceptance until Ctrl-C")
    args = parser.parse_args()
    try:
        database_url, redis_url = checked_targets()
    except Exception:
        print("Refusing unsafe or incomplete disposable database/Redis configuration.", file=sys.stderr)
        return 2
    if args.check_config:
        print("Disposable target configuration accepted; no connection or mutation performed.")
        return 0

    # macOS aliases /tmp to /private/tmp. Use one canonical boundary for the
    # configured artifact root and the application's resolved export paths.
    output = Path(tempfile.mkdtemp(prefix="hawk-integration-", dir=os.getenv("RUNNER_TEMP", "/tmp"))).resolve()
    test_home = output / "home"
    test_home.mkdir()
    env = {key: os.environ[key] for key in ("PATH", "LANG", "TMPDIR") if key in os.environ}
    acceptance_url = make_url(database_url).set(database=ACCEPTANCE_DATABASE).render_as_string(hide_password=False)
    redis_parts = urlsplit(redis_url)
    env.update({
        "HOME": str(test_home), "ENV": "test", "TEST_PROFILE": "integration", "PYTHONDONTWRITEBYTECODE": "1", "TZ": "UTC",
        "PYTHONPATH": os.pathsep.join((str(ROOT), str(API))),
        "DATABASE_URL": database_url, "TEST_DATABASE_URL": database_url,
        "PHASE5_ACCEPTANCE_DATABASE_URL": acceptance_url,
        "REDIS_URL": redis_url, "TEST_REDIS_URL": redis_url,
        "CELERY_BROKER_URL": redis_parts._replace(path="/1").geturl(),
        "CELERY_RESULT_BACKEND": redis_parts._replace(path="/2").geturl(),
        "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS": "true", "FAIL_SECURE_MODE": "true",
        "SELF_REGISTRATION_ENABLED": "true", "SECRET_KEY_LOCK_ENABLED": "true",
        "SECRET_KEY_LOCK_FILE": str(output / "secret_key.lock"),
        "SECRET_KEY": secrets.token_hex(32),
        "CONNECTOR_SECRETS_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "CONNECTOR_SECRETS_KDF_SALT": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode(),
        "ONPREM_BUNDLE_SIGNING_SECRET": secrets.token_hex(32),
        "CANONICAL_ACTION_BINDING_KEY": secrets.token_hex(20),
        "SIMULATION_EVIDENCE_DIR": str(output / "simulation-evidence"),
        "ARTIFACT_DIR": str(output / "artifacts"),
        "E2E_SUMMARY_PATH": str(output / "e2e-summary.json"),
    })
    (output / "artifacts").mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        api_port = listener.getsockname()[1]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        web_port = listener.getsockname()[1]
    if args.web or args.browser_smoke:
        env.update({"NEXT_PUBLIC_API_URL": f"http://127.0.0.1:{api_port}",
                    "CORS_ORIGINS": f"http://127.0.0.1:{web_port}",
                    "WEB_ORIGIN": f"http://127.0.0.1:{web_port}",
                    "FRONTEND_URL": f"http://127.0.0.1:{web_port}",
                    "NEXT_TELEMETRY_DISABLED": "1"})
    report: dict = {"output_directory": str(output), "steps": [], "passed": False}
    processes: list[tuple[subprocess.Popen, object]] = []

    def run(name: str, command: list[str], overrides: dict | None = None) -> None:
        with (output / f"{name}.log").open("w") as log:
            result = subprocess.run(command, cwd=API, env={**env, **(overrides or {})}, stdout=log, stderr=subprocess.STDOUT)
        report["steps"].append({"step": name, "returncode": result.returncode})
        print(f"{name}: exit {result.returncode}", flush=True)
        if result.returncode:
            raise RuntimeError(f"{name} failed; inspect its log")

    def start(name: str, module_args: list[str], *, component: str = "api") -> None:
        log = (output / f"{name}.log").open("w")
        process = subprocess.Popen([sys.executable, "-m", *module_args], cwd=API, env={**env, "COMPONENT_TYPE": component}, stdout=log, stderr=subprocess.STDOUT)
        processes.append((process, log))

    try:
        engine = create_engine(database_url, isolation_level="AUTOCOMMIT", hide_parameters=True, connect_args={"connect_timeout":5})
        try:
            with engine.connect() as connection:
                version = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
                if not 160000 <= version < 170000:
                    raise RuntimeError("PostgreSQL 16 is required for the acceptance tests")
                tables = connection.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")).scalar_one()
                exists = connection.execute(text("SELECT 1 FROM pg_database WHERE datname=:name"), {"name": ACCEPTANCE_DATABASE}).first()
                if tables or exists:
                    raise RuntimeError("Refusing reused databases; provide fresh disposable PostgreSQL services")
                connection.exec_driver_sql(f'CREATE DATABASE "{ACCEPTANCE_DATABASE}"')
        finally:
            engine.dispose()
        run("migrations", [sys.executable, "-m", "alembic", "-c", "app/db/migrations/alembic.ini", "upgrade", "head"])
        run("acceptance-migrations", [sys.executable, "-m", "alembic", "-c", "app/db/migrations/alembic.ini", "upgrade", "head"], {"DATABASE_URL": acceptance_url, "TEST_DATABASE_URL": acceptance_url})
        run("seed", [sys.executable, str(ROOT / "infra/scripts/seed.py")])
        run("seed-e2e", [sys.executable, str(ROOT / "infra/scripts/seed_e2e_fixtures.py")])
        start("worker", ["celery", "-A", "app.jobs.celery_app.celery_app", "worker", "--pool=solo", "--concurrency=1", "--loglevel=info", "-Q", "default,monitoring,auditor,discovery"], component="worker")
        start("beat", ["celery", "-A", "app.jobs.celery_app.celery_app", "beat", "--loglevel=info", "--schedule", str(output / "celerybeat-schedule")], component="celery_beat")
        port = api_port
        start("api", ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"])
        from redis import Redis
        from redis.exceptions import RedisError
        redis = Redis.from_url(redis_url)
        for _ in range(90):
            if any(process.poll() is not None for process, _ in processes):
                raise RuntimeError("An owned test service exited; inspect API/worker/beat logs")
            try:
                beats = [float(redis.get(key) or 0) for key in ("control_plane:celery:worker_heartbeat", "control_plane:celery:beat_heartbeat")]
                fresh = all(0 <= time.time() - stamp < 120 for stamp in beats)
                with urlopen(f"http://127.0.0.1:{port}/health/ready", timeout=2) as response:
                    ready = response.status == 200
                if ready and fresh:
                    report["api_ready_and_real_worker_beat_heartbeats"] = True
                    break
            except (OSError, ValueError, RedisError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Strict API readiness or genuine worker/beat heartbeat did not pass")
        for component in ("worker", "celery_beat"):
            run(f"{component}-compatibility", [sys.executable, str(ROOT / "infra/scripts/check_component_heartbeat.py"), component], {"COMPONENT_TYPE": component})
        run("strict-control-plane-health", [sys.executable, "-c", "from app.db.session import SessionLocal; from app.services.control_plane_health_service import evaluate_control_plane_health; db=SessionLocal(); report=evaluate_control_plane_health(db); db.close(); assert report.healthy, {k:v.status for k,v in report.checks.items() if not v.ok}"])
        run("integration-tests", [sys.executable, "-m", "pytest", "-vv", "--tb=short", "-m", "integration", "tests/", f"--junitxml={output / 'integration.xml'}"])
        cases = [case for case in ET.parse(output / "integration.xml").iter("testcase") if "test_phase5_postgresql_acceptance" in case.get("classname", "")]
        if len(cases) != 4 or any(case.find("skipped") is not None for case in cases):
            raise RuntimeError("All four PostgreSQL acceptance tests must run without skips")
        report["phase5_acceptance_tests_executed"] = len(cases)
        report["api_url"] = f"http://127.0.0.1:{port}"
        if args.web or args.browser_smoke:
            web = ROOT / "apps/web"
            run("web-unit", ["npm", "--prefix", str(web), "run", "test:ui"])
            run("web-build", ["npm", "--prefix", str(web), "run", "build"])
            web_log = (output / "web.log").open("w")
            processes.append((subprocess.Popen(["node", str(web / "node_modules/next/dist/bin/next"), "start", "--hostname", "127.0.0.1", "--port", str(web_port)],
                                              cwd=web, env=env, stdout=web_log, stderr=subprocess.STDOUT), web_log))
            report["web_url"] = f"http://127.0.0.1:{web_port}"
            for _ in range(60):
                try:
                    with urlopen(f"{report['web_url']}/login", timeout=2) as response:
                        if response.status == 200: break
                except OSError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("Owned web server did not become ready")
            if args.browser_smoke:
                overrides = {"HAWK_BROWSER_EXECUTABLE": str(args.browser_executable.resolve())} if args.browser_executable else {}
                run("web-browser", ["node", str(ROOT / "tools/collaboration/native_browser_smoke.cjs"),
                                    report["api_url"], report["web_url"], str(output)], overrides)
        report["passed"] = True
        if args.serve:
            print(json.dumps({"development_stack_ready": True, "api": report["api_url"],
                              "web": report.get("web_url"), "private_logs": str(output),
                              "scope": "Disposable local fixture data; Ctrl-C stops only owned services"}), flush=True)
            try:
                while True:
                    if any(process.poll() is not None for process, _ in processes):
                        raise RuntimeError("An owned development service exited")
                    time.sleep(1)
            except KeyboardInterrupt:
                report["operator_stopped_after_acceptance"] = True
    except Exception as exc:
        report["passed"] = False
        report["error_class"] = type(exc).__name__
        # Driver errors can contain connection credentials; do not print them.
        if isinstance(exc, RuntimeError):
            report["failure"] = str(exc)
    finally:
        for process, log in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            log.close()
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
