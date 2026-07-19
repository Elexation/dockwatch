FROM --platform=$BUILDPLATFORM golang:1.26.5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
# Defaults mirror cmd/dockwatch/main.go.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
	-ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
	-o /out/dockwatch ./cmd/dockwatch

FROM scratch
# CA roots for registry/ntfy HTTPS.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dockwatch /dockwatch
# Root on purpose: non-root can't open the socket or the auto-created bind dirs.
HEALTHCHECK CMD ["/dockwatch", "health"]
ENTRYPOINT ["/dockwatch"]
