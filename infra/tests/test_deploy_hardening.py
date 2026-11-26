"""The one-machine install (deploy/compose.yaml, infra/Dockerfile.*, deploy/install.sh) stays hardened to the CIS Docker
Benchmark, the CIS PostgreSQL benchmark's container-level items and Redis's security advice, and the release keeps
making signed SBOMs and scanning its images (NIST SSDF). Each test names the items it guards, so that none of them can
be undone by accident."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "deploy/compose.yaml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
LONG_RUNNING = [name for name in SERVICES if name != "migrate"]
HAWK_IMAGES = ["proxy", "web", "migrate", "api", "worker", "beat", "updater"]
THIRD_PARTY = ["postgres", "redis"]
DOCKERFILES = {name: ROOT / f"infra/Dockerfile.{name}" for name in ("api", "web", "proxy", "updater")}
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


# ---- CIS Docker Benchmark, section 5 (container runtime) -------------------------------------------------------------


@pytest.mark.parametrize("name", list(SERVICES))
def test_every_container_has_no_capabilities_no_privilege_escalation_and_is_not_privileged(name: str) -> None:
    """CIS 5.3 (capabilities), 5.4 (privileged), 5.25 (no-new-privileges)."""

    service = SERVICES[name]
    assert service.get("cap_drop") == ["ALL"], name
    assert not service.get("cap_add"), f"{name} adds capabilities"
    assert "no-new-privileges:true" in service.get("security_opt", []), name
    assert service.get("privileged") is not True, name
    for key in ("pid", "ipc", "uts", "userns_mode", "cgroup"):
        assert service.get(key) != "host", f"{name} shares the host's {key} namespace (CIS 5.8, 5.15, 5.16, 5.20, 5.30)"
    assert service.get("network_mode") != "host", f"{name} uses the host's network (CIS 5.9)"
    assert not service.get("devices"), f"{name} is given host devices (CIS 5.17)"


@pytest.mark.parametrize("name", list(SERVICES))
def test_every_container_runs_as_a_fixed_non_root_user(name: str) -> None:
    """CIS 4.1: a user for the container; fixed UIDs so volumes and secrets keep their owners."""

    user = str(SERVICES[name].get("user", ""))
    assert re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user), f"{name} runs as {user or 'the image default'}"
    expected = "999:999" if name in THIRD_PARTY else "1000:1000"
    assert user == expected, name


@pytest.mark.parametrize("name", list(SERVICES))
def test_every_root_file_system_is_read_only_with_explicit_scratch_space(name: str) -> None:
    """CIS 5.13: read-only root file system; only volumes and tmpfs are writable."""

    service = SERVICES[name]
    assert service.get("read_only") is True, name
    assert "/tmp" in [entry.split(":")[0] for entry in service.get("tmpfs", [])], name


@pytest.mark.parametrize("name", list(SERVICES))
def test_every_container_has_memory_cpu_and_process_limits(name: str) -> None:
    """CIS 5.10 (memory), 5.11 (CPU priority), 5.29 (PIDs cgroup limit)."""

    service = SERVICES[name]
    assert service.get("mem_limit"), f"{name} has no memory limit"
    assert int(service.get("cpu_shares", 0)) > 0, f"{name} has no CPU weight"
    assert 0 < int(service.get("pids_limit", 0)) <= 512, name


@pytest.mark.parametrize("name", LONG_RUNNING)
def test_every_long_running_service_has_a_health_check_and_a_restart_policy(name: str) -> None:
    """CIS 4.6 (HEALTHCHECK), 5.27 (health status checked), 5.15 (restart policy: unless-stopped, never always)."""

    service = SERVICES[name]
    check = service.get("healthcheck") or {}
    assert check.get("test") and not check.get("disable"), name
    assert service.get("restart") == "unless-stopped", name
    assert service.get("logging", {}).get("options", {}).get("max-size"), f"{name} has no log rotation"


def test_third_party_images_are_pinned_by_digest_and_hawk_images_are_ours() -> None:
    """CIS 4.2 / 5.28 (trusted, verified base images): postgres and redis by digest."""

    for name in THIRD_PARTY:
        assert DIGEST.search(SERVICES[name]["image"]), f"{name}: {SERVICES[name]['image']}"
    for name in HAWK_IMAGES:
        assert SERVICES[name]["image"].startswith("${HAWK_"), name


@pytest.mark.parametrize("name", list(DOCKERFILES))
def test_every_dockerfile_pins_its_bases_runs_non_root_and_has_a_health_check(name: str) -> None:
    """CIS 4.1 (USER), 4.2 (pinned base), 4.6 (HEALTHCHECK), 4.7 (no lone apt-get update), 4.9 (COPY, not ADD)."""

    source = DOCKERFILES[name].read_text(encoding="utf-8")
    for line in re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", source, re.MULTILINE):
        if re.fullmatch(r"[a-z-]+", line):  # an earlier stage of the same file
            continue
        assert DIGEST.search(line), f"{name}: FROM {line}"
    runtime = source.split(" AS runtime", 1)[1].split("\nFROM ", 1)[0]
    users = re.findall(r"^USER\s+(\S+)", runtime, re.MULTILINE)
    assert users and users[-1] in ("1000", "1000:1000"), f"{name}: the runtime stage ends as {users}"
    assert "HEALTHCHECK" in runtime, name
    assert not re.search(r"^ADD\s", source, re.MULTILINE), name
    assert not re.search(r"apt-get update\s*$", source, re.MULTILINE), name


def test_no_secret_is_written_into_compose_or_the_images() -> None:
    """CIS 4.10 (no secrets in Dockerfiles), 5.x: the application's secrets come from files (Docker secrets)."""

    compose = text("deploy/compose.yaml")
    for word in ("PASSWORD", "SECRET", "TOKEN", "KEY", "PASS"):
        for match in re.finditer(rf"^\s+([A-Z_]*{word}[A-Z_]*):\s*(.+)$", compose, re.MULTILINE):
            value = match.group(2).split("#")[0].strip().strip('"')
            assert value == "" or value.startswith("${") or value.startswith("/run/") or value in ("true", "false"), match.group(0)
    for dockerfile in DOCKERFILES.values():
        source = dockerfile.read_text(encoding="utf-8")
        assert not re.search(r"^(ENV|ARG)\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY)\S*=\S+", source, re.MULTILINE), dockerfile.name
        # The build's CA certificate is a build secret (never a layer).
        for line in re.findall(r"^COPY .*$", source, re.MULTILINE):
            assert not re.search(r"\.(pem|key|crt|pfx)\b|secrets", line), line
    for ignore in (".dockerignore", "infra/Dockerfile.api.dockerignore", "infra/Dockerfile.web.dockerignore"):
        entries = text(ignore).splitlines()
        for pattern in ("**/.env", "secrets", "**/*.pem", "**/*.key", "deploy/.env"):
            assert pattern in entries, f"{ignore} lets {pattern} into the build"


def test_postgres_and_redis_are_only_on_the_internal_network_and_nothing_but_the_proxy_publishes() -> None:
    """CIS 5.7 / 5.14 (only the needed ports, on the needed interface), network segmentation."""

    networks = COMPOSE["networks"]
    assert networks["hawk-internal"]["internal"] is True
    assert networks["hawk"].get("internal") is not True
    for name in THIRD_PARTY:
        assert SERVICES[name]["networks"] == ["hawk-internal"], name
    for name in ("api", "worker", "beat", "migrate"):
        assert set(SERVICES[name]["networks"]) == {"hawk", "hawk-internal"}, name
    for name in ("proxy", "web"):
        assert SERVICES[name]["networks"] == ["hawk"], name
    published = [name for name, service in SERVICES.items() if service.get("ports")]
    assert published == ["proxy"]
    for port in SERVICES["proxy"]["ports"]:
        assert port.startswith("${BIND_ADDRESS:-127.0.0.1}:"), port


def test_the_updater_keeps_the_docker_socket_isolated() -> None:
    """CIS 5.31 (Docker socket): the one documented exception, with no network, a non-root user in the socket's group,
    and nothing else; deploy/install.sh never starts an updater that cannot put two-network services back."""

    updater = SERVICES["updater"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in updater["volumes"]
    assert updater["network_mode"] == "none" and "networks" not in updater
    assert updater["group_add"] == ["${HAWK_DOCKER_GID:-0}"]
    assert updater["profiles"] == ["updates"]
    others = [name for name, service in SERVICES.items() if name != "updater" and any("docker.sock" in str(v) for v in service.get("volumes", []))]
    assert others == []
    assert "CIS Docker 5.31" in text("deploy/compose.yaml")
    assert 'LABEL org.cxsmtp.hawk.updater.networks="many"' in DOCKERFILES["updater"].read_text(encoding="utf-8")
    install = text("deploy/install.sh")
    assert "org.cxsmtp.hawk.updater.networks" in install and 'HAWK_DOCKER_GID="$(stat -c %g /var/run/docker.sock' in install


# ---- CIS PostgreSQL (container level) and Redis ---------------------------------------------------------------------


def test_postgres_signs_in_with_scram_over_tls_and_logs_connections() -> None:
    """CIS PostgreSQL 3.1.x (logging), 4.x / 6.x (scram-sha-256, TLS), and no trust or md5 in the hba file."""

    postgres = SERVICES["postgres"]
    settings = dict(arg.split("=", 1) for arg in postgres["command"] if "=" in arg)
    assert postgres["command"][0] == "postgres"
    assert settings["password_encryption"] == "scram-sha-256"
    assert settings["ssl"] == "on" and settings["ssl_min_protocol_version"] == "TLSv1.2"
    assert settings["log_connections"] == "on" and settings["log_disconnections"] == "on"
    prefix = settings["log_line_prefix"]
    for escape in ("%m", "%p", "%u", "%d", "%h"):
        assert escape in prefix, escape
    assert settings["log_statement"] == "ddl"
    assert settings["hba_file"] == "/etc/hawk/pg_hba.conf"
    assert "./postgres-hba.conf:/etc/hawk/pg_hba.conf:ro" in postgres["volumes"]
    assert "--auth-host=scram-sha-256" in postgres["environment"]["POSTGRES_INITDB_ARGS"]
    rules = [line.split() for line in text("deploy/postgres-hba.conf").splitlines() if line.strip() and not line.startswith("#")]
    assert rules == [
        ["local", "all", "all", "scram-sha-256"],
        ["hostssl", "all", "all", "all", "scram-sha-256"],
        ["host", "all", "all", "all", "reject"],
    ]
    assert {"postgres_tls_cert", "postgres_tls_key"} <= set(postgres["secrets"])
    install = text("deploy/install.sh")
    assert "postgres_tls.key" in install and 'chmod 0600 "$SECRETS/postgres_tls.key"' in install
    # The image deploy/install.sh falls back on for openssl is the one compose runs.
    assert re.search(r"sed -n 's/\^    image: \\\(postgres:", install)


def test_redis_has_a_password_protected_mode_and_no_dangerous_commands() -> None:
    command = " ".join(SERVICES["redis"]["command"])
    assert "--requirepass" in command and "/run/secrets/redis_password" in command
    assert "--protected-mode yes" in command
    for name in ("FLUSHALL", "FLUSHDB", "CONFIG", "DEBUG", "KEYS"):
        assert f"--rename-command {name} ''" in command, name


def test_the_application_never_needs_the_redis_commands_that_are_switched_off() -> None:
    pattern = re.compile(r"\.(flushall|flushdb|config_set|config_get|config_rewrite|debug_object|keys)\(\s*['\"]")
    found = [str(path.relative_to(ROOT)) for path in (ROOT / "apps/api/app").rglob("*.py") if pattern.search(path.read_text(encoding="utf-8"))]
    assert found == []


# ---- The installer's host checks (CIS Linux items, reported only) ----------------------------------------------------


def test_the_installer_reports_the_hosts_cis_items_to_the_self_check() -> None:
    install = text("deploy/install.sh")
    for check in ("firewall", "ssh-root", "ssh-passwords", "updates", "time-sync", "disk-encryption", "auditd"):
        assert f"host_check {check} pass" in install and f"host_check {check} warn" in install, check
    assert '"$HAWK_DATA_DIR/updater/host-check.json"' in install
    assert 'HOST_CHECK_FILE = "host-check.json"' in text("apps/api/app/services/self_check.py")


def test_install_script_parses() -> None:
    result = subprocess.run(["bash", "-n", str(ROOT / "deploy/install.sh")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_compose_file_is_valid_for_docker_compose(tmp_path: Path) -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "deploy/compose.yaml"), "--profile", "updates", "config", "--quiet"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HAWK_DATA_DIR": str(tmp_path), "HOME": str(tmp_path)},
    )
    if "docker: 'compose' is not a docker command" in result.stderr:
        pytest.skip("the compose plugin is not installed")
    assert result.returncode == 0, result.stderr


# ---- Supply chain: SBOMs and the container scan (NIST SSDF PS.3, PW.4, RV.1) -----------------------------------------


def workflow(name: str) -> dict:
    return yaml.safe_load(text(f".github/workflows/{name}"))


def all_uses(document: dict) -> list[str]:
    return [step["uses"] for job in document["jobs"].values() for step in job.get("steps", []) if "uses" in step]


def test_every_workflow_action_is_pinned_by_commit() -> None:
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        for uses in all_uses(yaml.safe_load(path.read_text(encoding="utf-8"))):
            if uses.startswith("./"):
                continue
            assert re.search(r"@[0-9a-f]{40}$", uses), f"{path.name}: {uses}"


def test_the_release_makes_signs_and_attaches_cyclonedx_sboms() -> None:
    release = workflow("release.yml")
    source = text(".github/workflows/release.yml")
    publish = [step for step in release["jobs"]["publish"]["steps"]]
    names = [step.get("name", "") for step in publish]
    assert "SBOM of the image, for amd64 and arm64" in names
    assert sum(1 for step in publish if str(step.get("uses", "")).startswith("actions/attest-sbom@")) == 2
    deps = release["jobs"]["dependency-sbom"]["steps"]
    assert sum(1 for step in deps if str(step.get("uses", "")).startswith("actions/attest-sbom@")) == 2
    assert "cyclonedx-json=sbom/hawk-api-python.cdx.json" in source and "cyclonedx-json=sbom/hawk-web-npm.cdx.json" in source
    assert release["jobs"]["release-sboms"]["permissions"] == {"contents": "write"}
    assert 'gh release upload "$TAG" sbom/*.cdx.json' in source
    # The tool is pinned and checksum-verified; the SBOMs are scanned for secrets before they are published.
    assert "syft_1.32.0_linux_amd64.tar.gz" in source and "d6400b579fa84dd383573b1d1ff6f081a37fc64d3ffaafdfdda95c4325f204be  syft.tgz" in source
    assert source.count("gitleaks dir sbom") == 2
    assert "SYFT_FILE_METADATA_SELECTION: none" in source


def test_images_are_scanned_and_a_fixable_high_or_critical_fails() -> None:
    grype = yaml.safe_load(text(".grype.yaml"))
    assert grype["fail-on-severity"] == "high" and grype["only-fixed"] is True
    for path in (".github/workflows/release.yml", ".github/workflows/security.yml"):
        source = text(path)
        assert "grype_0.99.1_linux_amd64.tar.gz" in source and "7fde4d45fe097daa2554078cd9e81faa43e51266a888337f5446c1ffc42d451f  grype.tgz" in source, path
        assert "--config .grype.yaml" in source, path
    smoke = workflow("release.yml")["jobs"]["smoke-test"]["steps"]
    scan = next(step for step in smoke if step.get("name") == "The image has no fixable High or Critical vulnerability")
    assert "continue-on-error" not in scan
