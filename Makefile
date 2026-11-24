TEST_COMPOSE_FILE := infra/docker-compose.acceptance.yml
TEST_PROJECT ?=
TEST_COMPOSE = docker compose -p "$(TEST_PROJECT)" -f $(TEST_COMPOSE_FILE)
UNIT_PYTEST := $(CURDIR)/.venv/bin/pytest
CONTAINER_PYTEST := pytest
API_PYTEST := PYTHONPATH=apps/api TEST_PROFILE=unit python3 -m pytest -q

ENTERPRISE_TEST_FILES := \
	apps/api/tests/test_api_contracts.py \
	apps/api/tests/test_contract_ai_systems.py \
	apps/api/tests/test_contract_policies.py \
	apps/api/tests/test_contract_ai_iam.py \
	apps/api/tests/test_extension_service_unit.py \
	apps/api/tests/test_extension_browser_telemetry.py \
	apps/api/tests/test_llm_gateway_integration.py \
	apps/api/tests/test_integrations_connectors.py \
	apps/api/tests/test_findings_pipeline.py \
	apps/api/tests/test_findings_traceability.py \
	apps/api/tests/test_simulation_scheduler.py \
	apps/api/tests/test_brain_golden.py \
	apps/api/tests/test_brain_findings_analyze.py \
	apps/api/tests/test_auditor_defensibility.py \
	apps/api/tests/test_auditor_snapshot_scope_rules.py \
	apps/api/tests/test_control_plane_health_dependency.py \
	apps/api/tests/test_fail_secure_mode.py \
	apps/api/tests/test_fail_secure_critical_routes.py \
	apps/api/tests/test_celery_hardening.py

.PHONY: require-test-project test test-unit test-integration test-all test-e2e test-integration-up test-integration-down wait-postgres wait-redis test-chaos test-route-hardening test-enterprise test-report test-report-e2e ci-integration test-full-suite platform-up platform-down platform-status platform-logs load-telemetry load-gateway load-findings

test: test-unit

test-unit:
	cd apps/api && \
	TEST_PROFILE=unit \
	DATABASE_URL=sqlite+pysqlite:///:memory: \
	TEST_DATABASE_URL=sqlite+pysqlite:///:memory: \
	PYTHONPATH=. \
	$(UNIT_PYTEST) -q -m "not integration"

require-test-project:
	@case "$(TEST_PROJECT)" in hawk-acceptance-?*) ;; *) echo 'Set TEST_PROJECT to a new hawk-acceptance-<unique-id> for disposable services.' >&2; exit 2;; esac

test-integration-up: require-test-project
	$(TEST_COMPOSE) up -d --wait db redis

test-integration-down: require-test-project
	$(TEST_COMPOSE) down

wait-postgres:
	@for i in $$(seq 1 60); do \
		if $(TEST_COMPOSE) exec -T db pg_isready -U postgres -d hawk_test >/dev/null 2>&1; then \
			echo "postgres is ready"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "postgres did not become ready in time" >&2; \
	exit 1

wait-redis:
	@for i in $$(seq 1 60); do \
		if $(TEST_COMPOSE) exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then \
			echo "redis is ready"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "redis did not become ready in time" >&2; \
	exit 1

test-integration: require-test-project
	$(TEST_COMPOSE) up --build --abort-on-container-exit --exit-code-from api

test-all: test-unit test-integration

test-e2e:
	./infra/scripts/run_e2e_harness.sh

test-chaos:
	$(API_PYTEST) apps/api/tests/test_control_plane_health_dependency.py apps/api/tests/test_fail_secure_mode.py apps/api/tests/test_fail_secure_critical_routes.py

test-route-hardening:
	$(API_PYTEST) apps/api/tests/test_health.py apps/api/tests/test_control_plane_health_dependency.py apps/api/tests/test_fail_secure_mode.py apps/api/tests/test_fail_secure_critical_routes.py

test-enterprise:
	$(API_PYTEST) $(ENTERPRISE_TEST_FILES)

test-report:
	python3 infra/scripts/test_report_summary.py

test-report-e2e:
	python3 infra/scripts/test_report_summary.py --include-extension-e2e

ci-integration:
	./infra/scripts/run_ci_integration.sh

test-full-suite:
	./infra/scripts/run_full_suite.sh

platform-up:
	./infra/scripts/start_platform_docker.sh

platform-down:
	docker compose -f infra/docker-compose.yml down

platform-status:
	docker compose -f infra/docker-compose.yml ps

platform-logs:
	docker compose -f infra/docker-compose.yml logs --tail=200 api worker celery-beat web

load-telemetry:
	python3 infra/scripts/load_telemetry_ingest.py --base-url $${BASE_URL:-http://localhost:8000} --requests $${REQUESTS:-200} --concurrency $${CONCURRENCY:-20}

load-gateway:
	python3 infra/scripts/load_gateway_request_path.py --base-url $${BASE_URL:-http://localhost:8000} --requests $${REQUESTS:-150} --concurrency $${CONCURRENCY:-10}

load-findings:
	python3 infra/scripts/load_findings_generation.py --base-url $${BASE_URL:-http://localhost:8000} --requests $${REQUESTS:-200} --concurrency $${CONCURRENCY:-20}
