# Authorized training target

This directory defines the only host the lab will ever assess.

```text
AUTHORIZED TARGET
http://localhost:3001
```

## What it runs

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) - a deliberately
vulnerable training application. It is **not** a real application and must never
be exposed beyond the machine running the lab.

The compose file publishes the container's port 3000 on **127.0.0.1:3001**, so
the application is reachable from the host but not from the local network.

> The container listens on port 3000 internally. The mapping is
> `127.0.0.1:3001:3000`, which is why the lab target is port **3001** on the
> host. Using `3001:3001` silently fails: the container is not listening there.

## Files

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | The container definition used by the lab scripts |

## Starting, checking and stopping

Use the lab scripts from the project root; they wrap the compose commands and
verify the result:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-target.ps1
powershell -ExecutionPolicy Bypass -File scripts/check-target.ps1
powershell -ExecutionPolicy Bypass -File scripts/stop-target.ps1
```

Equivalent raw commands:

```bash
docker compose -f target/docker-compose.yml up -d
docker compose -f target/docker-compose.yml ps
docker compose -f target/docker-compose.yml down
```

## Verifying the target yourself

The lab refuses to run a scan until the target answers:

```bash
python -m bcssl validate-target
```

Expected output:

```text
AUTHORIZED TARGET
  http://localhost:3001
  host=localhost port=3001 scheme=http
  resolved to: ::1, 127.0.0.1
  TARGET REACHABLE (HTTP 200)
```

If the target is not running you will see `TARGET UNREACHABLE` and every scan
will stop with that status instead of reporting findings.

## Startup time

Juice Shop initialises its database on first start and can take 30-90 seconds
before it answers. `scripts/start-target.ps1` waits and polls until it responds,
so a slow start is not an error.

## Safety notes

- The port binding is fixed to loopback. Do not change it to `0.0.0.0`.
- The container runs with `no-new-privileges`.
- No external challenge or AI service is required for the standard exercise set.
- If the host has limited resources, reduce the Docker Desktop memory
  allocation rather than changing the port mapping.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Container exits immediately | `docker compose -f target/docker-compose.yml logs juice-shop` |
| Port 3001 already in use | Stop the process using 3001, then restart the container |
| `docker compose` not found | Use `docker-compose`, or start Docker Desktop first |
| Container healthy but connection refused | Juice Shop is still initialising; wait and re-check |
