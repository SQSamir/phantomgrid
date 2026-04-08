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
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace --all-features

migrate:
	docker compose exec postgres psql -U $${POSTGRES_USER} -d $${POSTGRES_DB} \
		-f /migrations/001_initial.sql

seed:
	docker compose exec api-gateway \
		curl -s -X POST http://localhost:8080/internal/seed \
		-H "X-Internal-Token: $${INTERNAL_SEED_TOKEN}"

keys:
	mkdir -p secrets
	openssl genrsa -out secrets/jwt_private.pem 4096
	openssl rsa -in secrets/jwt_private.pem -pubout -out secrets/jwt_public.pem
	@echo "Keys generated in secrets/"

check:
	cargo check --workspace

fmt:
	cargo fmt --all

audit:
	cargo audit

logs:
	docker compose logs -f --tail=100
