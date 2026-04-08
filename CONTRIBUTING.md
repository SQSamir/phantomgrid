# CONTRIBUTING

## Local dev

```bash
cp .env.example .env
docker compose up -d
```

## Code quality

- Keep commits small and scoped
- Use descriptive commit messages (`feat(scope): ...`)
- Prefer explicit error handling (no panic in service paths)

## PR checklist

- [ ] Service builds
- [ ] Compose file updated if service changed
- [ ] README/docs updated
