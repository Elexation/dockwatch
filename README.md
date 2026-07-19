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

### Behind a reverse proxy

[compose.hub-proxy.yml](examples/compose.hub-proxy.yml) publishes the UI on loopback
only and expects the proxy to terminate TLS. Set `DW_TRUSTED_PROXY=true` and point
`DW_DOMAIN` at the public hostname.

### Watching other machines

Add one `DW_AGENT_<NAME>_URL` per remote machine to the hub, e.g.
`DW_AGENT_HOME_URL=https://10.27.27.8:7443`. On its next start the hub mints
`certs/agents/<name>/bundle.pem`; copy that one file into `./certs` on the agent host
and run [compose.agent.yml](examples/compose.agent.yml) there. The agent serves a
single mutual-TLS route and makes no outbound connections.

Optional defense in depth: restrict the agent port (7443) to the hub's IP in the host
firewall. DockWatch is secure without it (mutual TLS), but the rule is free.

## Moving the image without a registry

Both distribution paths are first-class: push to any registry, or ship the image over
SSH:

```
docker save dockwatch | ssh <host> docker load
```

## License

[AGPL-3.0](LICENSE)
