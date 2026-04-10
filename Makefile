dev:
	docker compose up -d
stop:
	docker compose down
clean:
	docker compose down -v --remove-orphans
build:
	docker compose build
logs:
	docker compose logs -f --tail=100
keys:
	mkdir -p secrets
	openssl genrsa -out secrets/jwt_private.pem 4096
	openssl rsa -in secrets/jwt_private.pem -pubout -out secrets/jwt_public.pem
	@echo "✓ JWT keypair hazırdır"
