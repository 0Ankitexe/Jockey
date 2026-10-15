# T150 Compose configuration — 2026-10-16

From the repository root:

```sh
target/compose-verification/docker-compose --env-file .env.example -f compose.yaml config --quiet
```

Exit 0. This standalone Compose binary validates only the configuration; no
service was started and no connected acceptance claim follows.
