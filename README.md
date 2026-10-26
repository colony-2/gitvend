# Gitvend

Gitvend gives agents controlled access to GitHub repositories without giving them
your GitHub token. Agents use ordinary Git with short-lived credentials that
specify which repositories and branches they may read, write, or create.

## Gitvend gateway

The gateway sits between agents and GitHub. It holds your upstream GitHub tokens,
checks each agent's signed permissions, and forwards authorized Git requests.
You can configure different upstream tokens for different organizations, deny
writes to protected branches, and control whether new repositories are created
publicly or privately with issues, projects, wiki, and pull requests enabled.

The gateway supports GitHub and GitHub Enterprise-compatible endpoints. It needs
no database or GitHub App. Agents connect over HTTPS; GitHub's own access and
branch rules continue to apply.

[Set up and use the gateway →](docs/gateway.md)

## JobDB plugin

The optional JobDB plugin issues Gitvend credentials for jobs automatically.
Configure a tenant's base permissions and extra permissions for its target cell
repository. JobDB workers can request a base token or a cell token; each token's
lifetime is limited by the job's verified lease authority.

The plugin keeps its signing key on the JobDB host, and the gateway verifies the
resulting tokens with the matching public key. Workers receive neither the
signing key nor the upstream GitHub token.

[Set up the JobDB plugin →](docs/jobdb-secret-provider.md)

## Install

Install the npm package on Linux or macOS (amd64 or arm64):

```sh
npm install -g @colony2/gitvend
gitvend version
jobdb-gitvend-secret-provider --help
```

The package installs prebuilt executables; no Go toolchain or source checkout is
required. npm installation needs Node.js 22+, `tar`, and enabled install scripts.
The JobDB command is needed only on the host where JobDB launches the plugin.

For installation without Node.js, download your platform's archive and checksums
from [GitHub Releases](https://github.com/colony-2/gitvend/releases). Verify the
archive, extract it, and place the executables you need on `PATH`. Choose a release
that includes `jobdb-gitvend-secret-provider` when using the plugin; older packages
may contain only `gitvend`.

For a container deployment, use the published image with the
[Docker Compose guide](docs/docker-compose.md).

## Guides

- [Gateway setup, Git usage, and operations](docs/gateway.md)
- [Repository creation controls](docs/gateway.md#repository-creation-defaults)
- [JobDB plugin setup and issuer configuration](docs/jobdb-secret-provider.md)
- [Permission syntax](docs/permission-syntax.md)
- [Docker Compose deployment](docs/docker-compose.md)
- [Developer guide: source builds, tests, and releases](docs/development.md)
