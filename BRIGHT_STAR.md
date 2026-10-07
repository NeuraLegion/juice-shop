# BRIGHT_STAR.md — Bright Agent run instructions for OWASP Juice Shop

Run-memory and operator instructions for Bright Agent (STAR). Juice Shop is a single
Node.js process backed by a file-based SQLite database, so under scan load it needs an
init process, an automatic restart policy, and resource caps to stay healthy. Build and
run it with the hardened wrapper below so it survives a full scan. All of this works with
Juice Shop's own source as-is.

## Startup

Build the application from this repository's own `Dockerfile`, wrapped in a hardened
Compose file. The wrapper is what keeps the target alive under load. Write the following
to `docker-compose.dast.yml` at the repo root and recreate it per run, then
`docker compose -f docker-compose.dast.yml up -d --build`:

```yaml
services:
  juice-shop:
    build:
      context: .                              # build from the repo's own Dockerfile
      dockerfile: Dockerfile
    init: true                                # PID-1 init reaps zombies, forwards signals
    restart: unless-stopped                   # a single crash auto-recovers; the scan continues
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: unsafe                        # keep all challenges active
      NODE_OPTIONS: "--max-old-space-size=1536"  # V8 heap below the container cap: GC/throw instead of OOM-kill
    mem_limit: 2g
    memswap_limit: 2g                         # no swap thrash
    cpus: "2.0"
    pids_limit: 512
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    healthcheck:
      test: ["CMD", "/nodejs/bin/node", "-e", "require('http').get('http://127.0.0.1:3000/rest/admin/application-version',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 90s
    tmpfs:
      - /juice-shop/logs:uid=65532,gid=65532
```

Two settings match this repo's distroless-based `Dockerfile` (base
`gcr.io/distroless/nodejs22-debian12`, `USER 65532`):

- The healthcheck invokes `/nodejs/bin/node` by absolute path, where the distroless image
  keeps the Node binary.
- The `tmpfs` logs mount sets `uid=65532,gid=65532` to match the container's non-root
  user, so the app can write `logs/`.

Keep these two values aligned with the `Dockerfile`'s base image and user.

Readiness: the target is up once `GET /rest/admin/application-version` returns HTTP 200.
First boot rebuilds and re-seeds the database, which takes ~60–90 s — wait for the 200
before scanning (this is why `start_period` is 90 s).

## Auth

- Login: `POST /rest/user/login` with JSON body
  `{"email": "<user>", "password": "<password>"}`. Success returns HTTP 200 with body
  `{"authentication": {"token": "<JWT>", ...}}`.
- Extract the JWT from the login response body (match `"token":"([^"]+)"`) and inject it
  into scan requests as the header `Authorization: Bearer <token>`.
- Session-check / test request: `GET /rest/basket/1` — returns 401 without a token and
  200 with a valid Bearer token.

## Credentials

- Default admin credentials for this training app: `admin@juice-sh.op` / `admin123`.
  (Well-known public Juice Shop defaults, safe for this deliberately-vulnerable target.
  For a real application, reference credentials by secret/variable name, not value.)

## Scan configuration (apply at scan launch)

Set the following in the scan-launch configuration (Bright API / `bright-cli` / scan
template). `BRIGHT_STAR.md` carries structured startup / auth / credentials / infra
instructions; scope and concurrency belong to the scan launch config, so configure them
there:

- **Exclude the authentication endpoint `POST /rest/user/login` from the attack scope.**
  Fuzzing it corrupts the request the auth session is minted from, which breaks scan-wide
  authentication. Keep read-only auth endpoints such as `GET /rest/user/whoami` in scope.
- **Exclude `/socket.io/` long-polling endpoints.** They hold connections open to the
  Repeater's request timeout; under scan load this can drop the Repeater↔cloud bridge and
  pause the scan. They are transport, not a useful attack surface here.
- **Re-authenticate on a genuine expired-session signal only (HTTP 401), not on 403.**
  Juice Shop returns 403 as a normal "authenticated but not allowed" response on many
  protected routes; treating 403 as session loss triggers unnecessary re-logins.
