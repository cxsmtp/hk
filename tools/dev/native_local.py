"""Start a fresh, Docker-free development/acceptance stack, owned by this process.

Never discovers existing databases or loads .env. A new private state directory
and explicit PostgreSQL 16/Redis 7 binaries are mandatory. Ctrl-C stops only this
invocation's child processes; its data and logs are preserved for inspection.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def fresh_state(path: Path) -> Path:
    path = path.expanduser().absolute()
    if any(c in str(path) for c in ('\n', '\r', '"', '\\')):
        raise ValueError("State path contains unsupported configuration characters")
    if path.exists() or path.is_symlink():
        raise ValueError("State directory must not exist; existing data is never reused")
    if path.parent.resolve() != path.parent or not path.parent.is_dir():
        raise ValueError("Use an existing, canonical, nonsymlink parent directory")
    return path


def executable(name: str, directory: Path | None = None) -> str:
    candidate = str(directory / name) if directory else shutil.which(name)
    if not candidate or not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
        raise ValueError(f"Missing executable: {name}; provide its binary directory or PATH")
    return str(Path(candidate).resolve())


def available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def reject_local_environment_files(root: Path) -> None:
    for directory in (root, root / "apps/api", root / "apps/web"):
        for path in directory.glob(".env*"):
            if not path.name.endswith(".example") and (path.is_file() or path.is_symlink()):
                raise ValueError("Use a clean checkout without local .env configuration files")


def tool_versions(pg_bin: Path | None, redis_bin: Path | None) -> dict:
    paths = {name: executable(name, pg_bin) for name in ("postgres", "initdb", "createdb", "pg_isready")}
    paths["redis-server"] = executable("redis-server", redis_bin)
    versions = {name: subprocess.check_output([paths[name], "--version"], text=True).strip()
                for name in ("postgres", "redis-server")}
    if not re.search(r"PostgreSQL\) 16\.", versions["postgres"]):
        raise ValueError("Use PostgreSQL 16, matching the migrated acceptance/CI contract")
    if not re.search(r"\bv=7\.", versions["redis-server"]):
        raise ValueError("Use Redis 7, matching the acceptance/CI contract")
    return {"paths": paths, "versions": versions}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Nonsecret native-local JSON template; CLI paths override it")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--postgres-bin", type=Path)
    parser.add_argument("--redis-bin", type=Path)
    parser.add_argument("--check", action="store_true", help="Read-only prerequisite checks")
    parser.add_argument("--web", action="store_true", help="Build/test/start the web console")
    parser.add_argument("--browser-smoke", action="store_true", help="Run fixture login and route checks; implies --web")
    parser.add_argument("--browser-executable", type=Path, help="Optional existing Chromium executable; no profile reuse")
    parser.add_argument("--serve", action="store_true", help="Keep the verified development stack running until Ctrl-C")
    args = parser.parse_args()
    try:
        if args.config:
            config = json.loads(args.config.read_text())
            allowed = {"state_dir", "postgres_bin", "redis_bin", "browser_executable"}
            if not isinstance(config, dict) or set(config) - allowed:
                raise ValueError("Native config supports only the four documented nonsecret path fields")
            for key, value in config.items():
                if value is not None and not isinstance(value, str):
                    raise ValueError("Native config paths must be strings or null")
                if value and getattr(args, key) is None: setattr(args, key, Path(value))
        if args.state_dir is None:
            raise ValueError("Provide a fresh --state-dir or the nonsecret JSON template")
        state = fresh_state(args.state_dir)
        tools = tool_versions(args.postgres_bin, args.redis_bin)
        reject_local_environment_files(ROOT)
        if args.web or args.browser_smoke:
            executable("node"); executable("npm")
            if not (ROOT / "apps/web/node_modules/next/package.json").is_file():
                raise ValueError("Run npm ci in apps/web first")
        if args.browser_smoke and not (ROOT / "extension/node_modules/playwright/package.json").is_file():
            raise ValueError("Run npm ci in extension and install its locked Chromium first")
        if args.browser_smoke:
            if not args.browser_executable:
                # Resolve the browser before replacing HOME for child isolation.
                browser_env = {key: os.environ[key] for key in ("PATH", "HOME", "PLAYWRIGHT_BROWSERS_PATH") if key in os.environ}
                value = subprocess.check_output(["node", "-p", "require('./extension/node_modules/playwright').chromium.executablePath()"],
                                                cwd=ROOT, env=browser_env, text=True).strip()
                args.browser_executable = Path(value)
            if not args.browser_executable.is_file() or not os.access(args.browser_executable, os.X_OK):
                raise ValueError("Locked Chromium is not installed; install it or provide --browser-executable")
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.check:
        print(json.dumps({"check": "passed", "versions": tools["versions"], "writes": False}))
        return 0

    state.mkdir(mode=0o700)
    home = state / "home"; home.mkdir(mode=0o700)
    logs = state / "logs"; logs.mkdir()
    pg_data = state / "postgres"
    pg_port, redis_port = available_port(), available_port()
    while redis_port == pg_port:
        redis_port = available_port()
    password = secrets.token_hex(32)
    pwfile = state / "postgres-password"
    pwfile.touch(mode=0o600); pwfile.write_text(password + "\n")
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
           "TMPDIR": str(state), "RUNNER_TEMP": str(state), "PGPASSWORD": password}
    report = {"source": str(ROOT), "state": str(state), "versions": tools["versions"],
              "ports": {"postgres": pg_port, "redis": redis_port}, "docker_used": False, "passed": False}
    children: list[tuple[subprocess.Popen, object]] = []

    def run(name: str, command: list[str]) -> None:
        with (logs / f"{name}.log").open("w") as log:
            result = subprocess.run(command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"{name} failed; inspect its private log")

    def start(name: str, command: list[str]) -> None:
        log = (logs / f"{name}.log").open("w")
        children.append((subprocess.Popen(command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT), log))

    try:
        run("initdb", [tools["paths"]["initdb"], "-D", str(pg_data), "--username=hawk_local",
                       "--auth-host=scram-sha-256", "--auth-local=scram-sha-256", "--pwfile", str(pwfile),
                       "--encoding=UTF8", "--locale=C"])
        pwfile.unlink()
        start("postgres", [tools["paths"]["postgres"], "-D", str(pg_data), "-h", "127.0.0.1",
                           "-p", str(pg_port), "-k", "", "-c", "timezone=UTC", "-c", "log_timezone=UTC"])
        from redis import Redis
        from redis.exceptions import RedisError
        for _ in range(60):
            if children[0][0].poll() is not None:
                raise RuntimeError("Owned PostgreSQL process exited; no existing service will be reused")
            p = subprocess.run([tools["paths"]["pg_isready"], "-h", "127.0.0.1", "-p", str(pg_port)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if p.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Owned PostgreSQL did not become ready")
        # Verify data-directory identity before creating/migrating any database.
        import psycopg2
        with closing(psycopg2.connect(host="127.0.0.1", port=pg_port, user="hawk_local", password=password, dbname="postgres")) as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW data_directory")
                if Path(cur.fetchone()[0]).resolve() != pg_data.resolve():
                    raise RuntimeError("PostgreSQL data identity does not match this invocation")
                cur.execute("SHOW timezone")
                report["postgres_timezone"] = cur.fetchone()[0]
                cur.execute("SHOW unix_socket_directories")
                report["postgres_unix_socket_directories"] = cur.fetchone()[0]
                if report["postgres_timezone"] != "UTC" or report["postgres_unix_socket_directories"]:
                    raise RuntimeError("Owned PostgreSQL must use UTC and TCP-only private test connectivity")
        run("createdb", [tools["paths"]["createdb"], "-h", "127.0.0.1", "-p", str(pg_port),
                         "-U", "hawk_local", "hawk_test"])
        redis_config = state / "redis.conf"
        redis_config.touch(mode=0o600)
        redis_config.write_text(f'bind 127.0.0.1\nprotected-mode yes\nport {redis_port}\ndir "{state}"\n'
                                'save ""\nappendonly no\ndaemonize no\n')
        start("redis", [tools["paths"]["redis-server"], str(redis_config)])
        for _ in range(60):
            if children[-1][0].poll() is not None:
                raise RuntimeError("Owned Redis exited; no existing service will be reused")
            try:
                client = Redis(host="127.0.0.1", port=redis_port, socket_timeout=1)
                directory = client.config_get("dir")["dir"]
                if isinstance(directory, bytes): directory = directory.decode()
                if client.ping() and Path(directory).resolve() == state.resolve():
                    break
            except (OSError, ValueError, RedisError):
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("Owned Redis identity/readiness did not pass")
        env.update({"HAWK_DISPOSABLE_TEST_ENV": "1",
                    "DATABASE_URL": f"postgresql+psycopg2://hawk_local:{password}@127.0.0.1:{pg_port}/hawk_test",
                    "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0"})
        command = [sys.executable, str(ROOT / "tools/dev/run_api_integration.py")]
        for option, enabled in (("--web", args.web or args.browser_smoke), ("--browser-smoke", args.browser_smoke), ("--serve", args.serve)):
            if enabled: command.append(option)
        if args.browser_executable:
            command += ["--browser-executable", str(args.browser_executable.resolve())]
        report["integration_returncode"] = subprocess.call(command, cwd=ROOT, env=env)
        report["passed"] = report["integration_returncode"] == 0
    except KeyboardInterrupt:
        report["interrupted_by_operator"] = True
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        if isinstance(exc, RuntimeError): report["failure"] = str(exc)
    finally:
        for process, log in reversed(children):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            log.close()
        if pwfile.exists(): pwfile.unlink()
        (state / "native-result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
