dev:
	docker compose up -d
build:
	docker compose build
stop:
	docker compose down
clean:
	docker compose down -v --remove-orphans
