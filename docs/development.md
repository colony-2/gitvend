# Developing Gitvend

This guide is for contributors and release maintainers. Users can install packages
and follow the [gateway guide](gateway.md) or [JobDB plugin guide](jobdb-secret-provider.md).

## Build and verify

Requires the Go version in `go.mod` and Git for the integration tests. Supported server platforms are Linux and macOS. Run these commands from the source checkout's root:

```sh
make build
export PATH="$PWD/bin:$PATH"
gitvend version
make check
```

`make check` runs race tests and vet. `make fuzz` exercises the permission, packet and JSON parsers. The default test suite uses real Git clients and a real `git-http-backend`, with a local GitHub API fixture; it needs neither a GitHub token nor external repository access.

## Install from source

For development or an unreleased revision, Go can build and install either command:

```sh
go install github.com/colony-2/gitvend/cmd/gitvend@latest
go install github.com/colony-2/gitvend/cmd/jobdb-gitvend-secret-provider@latest
```

Use a revision containing the desired changes. Add `$(go env GOPATH)/bin` to `PATH`
if necessary. Local gateway builds report their Git revision when available;
release builds of both commands report the release version.

## JobDB plugin development

```sh
make check-jobdb-provider
```

Tests verify grants and effective expiry with Gitvend's actual verifier, tenant
and principal checks, metadata injection rejection, concurrent reloads, key
rotation, invalid-file recovery, and the built executable's real JobDB plugin
handshake and live reload. The executable lives in
`cmd/jobdb-gitvend-secret-provider`, with Cobra commands in its `internal/cmd`
package. Credential issuance and reloads live in the reusable `pkg/jobdbprovider`
package. `Load` creates a fixed provider; `WatchConfig` creates a reloadable one
that must be closed when finished. Both implement `jobdb.SecretProvider`.

The plugin shares the root Go module and Gitvend signing implementation.
`go test ./...`, `go vet ./...`, and `make check` include it automatically.
`make build` builds both executables; `make build-jobdb-provider` builds only
the plugin. The gateway executable does not import the JobDB provider package.

## Container development

From the checkout, build the local image and start Compose:

```sh
export GITHUB_TOKEN='your-github-access-token'
GITVEND_IMAGE=gitvend:local docker compose up -d --build
```

See the [deployment guide](docker-compose.md) for configuration and key handling.
The published container runs the gateway; JobDB launches its plugin locally on
its own host, using the release archive or npm package.

## Container tests

`make check` tests concurrent initialization, recovery, corrupt state rejection,
key reuse and token verification, plus the existing gateway suite.
`make test-compose` builds and tests an isolated Compose project with a fake
GitHub token environment variable and no local config: startup, health,
on-demand issuance, volume isolation, denied
requests, and JWT survival across container recreation. It requires Docker,
Compose v2 or newer and Python 3, uses no GitHub credentials, and removes only its own
test volumes. CI runs it before releases.

## Verification scope

The automated tests cover real Git v2 discovery/clone/fetch, shallow and partial clones, known-hash reads, standard pushes, ref filtering, mixed denied pushes, tags, deletion, force updates, atomic and partial push outcomes, creation races/recovery, JWT tampering/expiry/size, secret/key reloads, independent replicas, name-based permissions and malformed/gzip requests. Parser fuzz targets and race checks are included.

Tests use local fixtures and do not establish live GitHub account permissions.
The [gateway compatibility section](gateway.md#compatibility) describes supported
Git features. See the [design](git-proxy-design.md) for requirements and tradeoffs.
[c2r](https://github.com/colony-2/c2r) informed the provisioning approach; Gitvend
uses a direct GitHub adapter and copies no c2r source.

## Release automation

The [release workflow](../.github/workflows/release.yaml) follows [c2j's release pattern](https://github.com/colony-2/c2j/blob/main/.github/workflows/release.yaml). Successful pushes to `main` in the `colony-2` organization run the test suite, automatically bump and push a version tag (patch by default), build both executables for four platforms, and publish GitHub release archives and checksums. It then publishes `@colony2/gitvend` to npm with `gitvend` and `jobdb-gitvend-secret-provider` commands after installing and smoke-testing the installed commands against the published assets. It also publishes Linux amd64/arm64 container images to `ghcr.io/colony-2/gitvend` with the release tag and `latest`, using `GITHUB_TOKEN` with package-write permission.

GitHub release/tag publication uses the workflow's `GITHUB_TOKEN`. Configure npm trusted publishing for `colony-2/gitvend`, workflow `release.yaml`, or provide an `NPM_TOKEN` with publishing access to `@colony2/gitvend`. The npm package must exist and its trusted publisher must be configured before token-free publication can work; bootstrap it with a token if needed.

macOS signing/notarization is optional. Set all five secrets to enable it: `MACOS_SIGN_P12`, `MACOS_SIGN_PASSWORD`, `APPLE_API_ISSUER`, `APPLE_API_KEY_ID`, and `APPLE_API_KEY`. No signing secrets skips this step; a partial configuration fails the build. Signing requires the matching Apple certificate and notarization credentials.

The reusable [test workflow](../.github/workflows/test.yml) runs Go race tests, vet, parser fuzzing, npm installer tests, and the Docker Compose smoke test. Run the installer tests locally with `npm test --prefix npm/gitvend` and the container checks with `make test-compose`. Release archive smoke tests also check all checksums and run both native executables' `version` commands before upload.

Copied release tooling retains its upstream Apache-2.0 license and attribution in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). This repository does not yet declare a project-wide license; npm metadata uses `UNLICENSED`.
