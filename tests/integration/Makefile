.PHONY: build test test-quickstart test-load clean

build:
	docker compose build

test: test-quickstart
	@echo "All integration tests passed."

test-quickstart: build
	@echo "=== E2E: Quickstart ==="
	@bash scripts/test_quickstart.sh

test-load: build
	@echo "=== E2E: Load test ==="
	@bash scripts/test_load.sh

clean:
	docker compose down -v --remove-orphans 2>/dev/null || true
	docker image prune -f 2>/dev/null || true
