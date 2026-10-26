# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=development
ARG COMMIT
ARG DATE
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -buildvcs=false -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/gitvend ./cmd/gitvend

FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 gitvend \
    && adduser -D -H -u 10001 -G gitvend gitvend \
    && mkdir -p /var/lib/gitvend/private /var/lib/gitvend/public \
    && chown -R 10001:10001 /var/lib/gitvend \
    && chmod 0700 /var/lib/gitvend/private /var/lib/gitvend/public
COPY --from=build /out/gitvend /usr/local/bin/gitvend
COPY deploy/gitvend.default.yaml /etc/gitvend/gitvend.yaml
USER 10001:10001
ENTRYPOINT ["gitvend"]
CMD ["serve", "--config", "/etc/gitvend/gitvend.yaml"]
