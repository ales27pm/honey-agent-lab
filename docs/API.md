# Optional local API

Install: `pip install -e '.[api]'`.

```bash
PYTHONPATH=src python -m honey_agent_lab serve
PYTHONPATH=src python -m honey_agent_lab serve --reload
```

Default bind is `127.0.0.1:8000`. Endpoints: `GET /health`, `GET /scenarios`, `POST /run/{scenario_name}`. The API accepts no code, URLs, arbitrary file paths, credentials, or external targets, and performs no outbound calls.

`--reload` is a development convenience and is allowed only on loopback hosts (`127.0.0.1`, `::1`, or `localhost`). It is rejected on non-loopback hosts even when `--allow-remote` is supplied.

Non-loopback binding without reload is refused unless `--allow-remote` is supplied explicitly. There is no authentication; remote binding is for trusted isolated lab networks only.
