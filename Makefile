dev:
	docker compose up -d
build:
	docker compose build
stop:
	docker compose down
clean:
	docker compose down -v --remove-orphans


prod:
	docker compose -f docker-compose.prod.yml up -d --build

lint:
	@echo "TODO: cargo fmt/clippy checks"

test:
	@echo "TODO: unit/integration tests"

migrate:
	@echo "Migrations run via service startup"

seed:
	@echo "TODO: seed default data"

logs:
	docker compose logs -f --tail=100
