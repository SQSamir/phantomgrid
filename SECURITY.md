# SECURITY

- Secrets from env only (`.env`), never hardcoded
- JWT RS256 keypair mounted from `secrets/`
- Parameterized SQL via sqlx
- Intended: mTLS for internal services (not fully implemented yet)
- Intended: strict RBAC in gateway and downstream services
- Intended: rate limiting and lockout policies in auth

> Note: this repo is in active build state; additional hardening is required before production.
