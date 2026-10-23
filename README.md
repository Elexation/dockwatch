# DockWatch

Self-hosted Docker image update monitor. A single static Go binary that watches running
containers, compares each image against its registry, and shows current vs. available
versions in a web dashboard. Sends one notification per new release and never updates
anything. It is a read-only observer.

## Build

The multi-stage `Dockerfile` is the only build path you need; the sole requirement is
Docker with buildx. The result is a `FROM scratch` image holding the static binary and
CA roots, nothing else.

```
docker buildx build -t dockwatch --load .
```

The binary is cross-compiled inside the build stage, so building for the other
architecture needs no emulation. Both `linux/amd64` and `linux/arm64` are supported:

```
docker buildx build --platform linux/arm64 -t dockwatch --load .
```

To stamp version information into `dockwatch version`:

```
docker buildx build -t dockwatch --load \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) .
```

## Deploy

Example compose files are in [examples/](examples/). Copy one into an empty directory
on the host; `./certs` and `./data` appear next to it on first start and hold the CA
and the state database, so keep them.

### Single machine

[compose.hub.yml](examples/compose.hub.yml) needs zero configuration:

```
docker compose -f compose.hub.yml up -d
```

Open `http://<host>:8080`; the first visit creates the admin account. Set
`DW_NTFY_TOPIC` to enable [ntfy](https://ntfy.sh) notifications.

Forgot the admin password? Set `DW_RESET_ADMIN=true` and recreate the container
(`docker compose up -d`; `docker compose restart` keeps the old environment), create
the account again, then remove the variable and recreate it once more. While the
variable is set, every start wipes the account and reopens setup to whoever reaches
the port first.

### Behind a reverse proxy

[compose.hub-proxy.yml](examples/compose.hub-proxy.yml) publishes the UI on loopback
only and expects the proxy to terminate TLS. Set `DW_TRUSTED_PROXY=true` and point
`DW_DOMAIN` at the public hostname.

### Watching other machines

Add one `DW_AGENT_<NAME>_URL` per remote machine to the hub, e.g.
`DW_AGENT_HOME_URL=https://192.0.2.10:7443`. On its next start the hub mints
`certs/agents/<name>/bundle.pem`; copy that one file into `./certs` on the agent host
and run [compose.agent.yml](examples/compose.agent.yml) there. The agent serves a
single mutual-TLS route and makes no outbound connections.

For a machine that is not always on, set `DW_AGENT_<NAME>_DOWN_ALERT=false` to skip
the "unreachable" notification for that agent. The dashboard still marks it
unreachable, and every other notification about it still fires.

Optional defense in depth: restrict the agent port (7443) to the hub's IP in the host
firewall. DockWatch is secure without it (mutual TLS), but the rule is free.

## Labels

Both labels go on the watched container (in that container's compose file), never on
DockWatch itself:

- `dw.watch: "false"` excludes the container from the dashboard and all checks.
- `dw.tags: "<regex>"` names which registry tags count as releases for that image,
  e.g. `dw.tags: '\d+\.\d+\.\d+'`. Some images mix dates, build ids, or variant
  suffixes into their version tags; when the dashboard shows a nonsensical "newer"
  version, this filter is the fix. The whole tag must match ([RE2
  syntax](https://github.com/google/re2/wiki/Syntax)), and an invalid pattern shows
  as a check error for that image. Only affects images watched by version number;
  mutable tags like `latest` are compared by digest and ignore it.

## API

The hub can serve a small JSON API for scripts and assistants; it is off by default.
Mint a token and give the hub only its SHA-256:

```
TOKEN=$(openssl rand -hex 24)
printf '%s' "$TOKEN" | sha256sum    # DW_API_TOKEN_SHA256 = these 64 hex characters
```

The client keeps the token and sends it as `Authorization: Bearer <token>`. A
48-character token can never be mistaken for the 64-character hash. Serve the API over
TLS (`DW_HTTPS`, or a proxy with `DW_TRUSTED_PROXY`); the hub warns at startup otherwise.

- `GET /api/v1/status` returns the dashboard as JSON: `hosts` with reachability and
  Docker status, `counts` per state, and one entry per watched container with its
  `state` (`update`, `republished`, `rate`, `error`, `current`, `local`, `auth`,
  `pending`). `checked_at` dates the registry check; on a host with
  `reachable: false`, the running versions are as of that host's `last_seen`.
- `POST /api/v1/check` starts a full check like the dashboard's Check now button, at
  most once per 5 minutes (otherwise 429 with `Retry-After`, or 409 while a check is
  already running). The response carries the current `last_cycle`; the check is done
  once the status `last_cycle` moves past it.

Fields are only ever added within `v1`.

## Moving the image without a registry

Both distribution paths are first-class: push to any registry, or ship the image over
SSH:

```
docker save dockwatch | ssh <host> docker load
```

## License

[AGPL-3.0](LICENSE)
