# PHANTOMGRID

Enterprise Cyber Deception Platform (microservice scaffold).

## Quick start (dev)

```bash
cp .env.example .env
docker compose up -d
```

## Production

```bash
cp .env.example .env
# fill secrets first
docker compose -f docker-compose.prod.yml up -d --build
```

### prod.infrahub.cz routing

- Frontend target: `127.0.0.1:3000`
- API/WS target: `127.0.0.1:8080`
- Ready-to-use Caddy block:
  - `deploy/CADDY_PROD_INFRAHUB.CADDYFILE`

## Services

- api-gateway: `:8080`
- auth-service: internal `:8081`
- decoy-manager: internal `:8082`
- honeypot-engine: `:10022`, `:18080`
- event-processor: internal
- alert-engine: internal
- mitre-mapper: `:8084`
- realtime: `:8085`
- analytics: `:8086`
- notifications: `:8087`
- tenant-manager: `:8088`
- integrations: `:8089`
- frontend: `:3000`

## Current implementation status

This repository currently contains a **working scaffold** and partial service implementations for Phases 1-5,
with Phase 6 hardening artifacts started (`docker-compose.prod.yml`, docs, env templates).
