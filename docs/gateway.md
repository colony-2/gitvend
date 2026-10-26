# Gitvend gateway guide

Gitvend is a Git/HTTPS gateway with permissions carried in signed JWTs. Agents use ordinary Git and one gateway credential across their assigned repositories. The gateway holds a shared upstream token and enforces repository, ref-discovery, branch-write, tag and repository-creation permissions before forwarding requests.

Implemented for GitHub and GitHub Enterprise-compatible APIs. Client and upstream Git connections use HTTPS; fetch/ref lookup requires protocol v2, while pushes use Git's normal receive-pack format. The service does not require a GitHub App. The gateway is stateless: it needs configuration, public verification keys and upstream credentials, with no database or writable state volume. Multiple instances can serve the same agents.

This guide takes an operator from configuring a gateway to giving an agent a credential, cloning a repository, and pushing an allowed branch.

[Install](#install) · [Docker Compose](docker-compose.md) · [Set up the gateway](#set-up-the-gateway) · [Issue a credential](#issue-an-agent-credential) · [Agent usage](#use-gitvend-as-an-agent) · [Permissions](#permission-strings) · [Operations](#provisioning-and-audit) · [Troubleshooting](#troubleshooting) · [CLI reference](#cli-reference)

## How credentials and permissions fit together

```text
Agent running Git -- HTTPS + agent JWT --> gitvend -- HTTPS + upstream token --> GitHub
                                            ^
                                  trusts the issuer's public key
```

| Credential | Who holds it | Purpose |
| --- | --- | --- |
| Upstream GitHub token | Gateway operator; available to the gateway process | Lets gitvend access repositories and, when enabled, create them. Shared across agents. |
| Ed25519 private signing key | Trusted orchestrator or operator | Signs each agent's JWT with its identity, expiry and permissions. |
| Ed25519 public signing key | Gateway | Verifies JWTs without contacting the issuer. |
| Agent JWT | The assigned agent | Used as its Git HTTPS password. Contains the signed permission strings. |

An operation must pass all configured checks: the provider's allowed owners, the signing key's allowed owners, the JWT's grants, gateway-wide deny rules, and the upstream account's permissions. A JWT cannot grant access outside these limits. Give agents their JWT; retain the upstream token on the gateway and the private signing key with the trusted issuer.

For JobDB workers, use the [JobDB plugin](jobdb-secret-provider.md) to issue
credentials automatically for each job lease. Follow that guide for issuer setup;
the gateway configuration, creation controls and agent Git usage here still apply.

Read permissions hide ungranted ref names; they do **not** isolate Git objects by branch. An agent with any read grant for a repository may fetch objects by known hash, subject to what the upstream serves. Use separate repositories when you need object confidentiality.

## Install

Install the published package on the gateway, the machine that issues credentials,
and agents that use the Git credential helper:

```sh
npm install -g @colony2/gitvend
gitvend version
```

The npm package downloads a prebuilt executable and verifies its SHA-256 checksum;
it requires Node.js 22+ and `tar`, with install scripts enabled. No Go toolchain
is needed. For installation without Node.js, download the Linux or macOS archive
for your amd64/arm64 system from [GitHub Releases](https://github.com/colony-2/gitvend/releases),
verify it against the release's `checksums.txt`, and put `gitvend` on `PATH`.
Archives include the example configurations and user guides.

For a container deployment using published images, follow the
[Docker Compose guide](docker-compose.md). That stack manages signing keys,
starts the gateway and provides an on-demand credential issuer.

## Set up the gateway

The walkthrough uses organization `fooorg`, an existing repository `project` with a `main` branch, and gateway address `git-gateway.example:8443`. Replace these with your own values. Commands assume `gitvend` is on `PATH`. Agents need Git with protocol v2 support; the gateway serves HTTPS directly in this example.

### 1. Provide the upstream token

Have your process supervisor or secret manager set `GITHUB_TOKEN` in the **gateway process** environment. The token's account must have access to the repositories the agents will use. For automatic creation, it must also be able to create repositories with the configured visibility in the organization and access them afterward. Gitvend does not generate or renew this upstream token.

GitHub's [token guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) describes account and organization restrictions. For private organization repository creation, GitHub documents `repo` scope for classic tokens or repository Administration write permission for fine-grained tokens; creation permissions alone do not establish Git read/write access. Check repository selection, organization approval and workflow-file access for your account. See [GitHub's create-repository requirements](https://docs.github.com/en/rest/repos/repos#create-an-organization-repository).

If you prefer a mounted token file, use this credential object inside the provider entry:

```yaml
credential:
  kind: token
  secret_ref: file:/run/secrets/github-token
```

The same credential is used for Git and REST API calls. An optional provider-level `api_credential` object with the same shape selects a separate REST token. This release supports token credentials; it does not use SSH keys or discover credentials from `gh auth` or Git credential helpers.

### 2. Generate and install the issuer key

On the trusted orchestrator or operator machine:

```sh
mkdir -p var
gitvend keygen --private var/signing.key --public var/signing.pub
```

Keep `var/signing.key` on that machine. Copy **only** `signing.pub` to `var/signing.pub` in the gateway's working directory. If the operator and gateway run on one machine, restrict the private key to the issuer's account. Each configured key has an ID and an issuer name; the token-signing command must use those exact values.

### 3. Configure and start the server

On the gateway, prepare the public-key directory and save the
[configuration template](../examples/gitvend.yaml) as `gitvend.yaml`. If you
downloaded a release archive, copy its included example:

```sh
mkdir -p var
cp examples/gitvend.yaml gitvend.yaml
```

Edit `gitvend.yaml` using this checklist:

| Field | Set it to |
| --- | --- |
| `listen` | `0.0.0.0:8443` to accept connections on the gateway's network interfaces. The template binds to `127.0.0.1:8443` for local access. |
| `tls_cert`, `tls_key` | Readable certificate/key files for `git-gateway.example`, trusted by the agents. |
| `keys[].public_key_file` | The public key installed in step 2. |
| `keys[].owners` and `providers[].allowed_owners` | Your lowercase organization names in both places. |
| `providers[].credential.secret_ref` | `env:GITHUB_TOKEN` or the mounted token file reference. |
| `providers[].allow_creation` | `true` for the scratch-repository example below; `false` to disable creation. |
| `providers[].creation_defaults` | Optional visibility and GitHub feature settings for new repositories; see [creation defaults](#repository-creation-defaults). |
| `denies` | Replace `fooorg` in the example deny rule too. It blocks updates/deletion of `main` and `master`. |

Configuration uses YAML. Unknown fields, duplicate keys, and multiple YAML documents are rejected. JSON-shaped mappings are also valid YAML and load through the same parser. Relative file paths are resolved from the server's **working directory**, not the configuration file's directory; use absolute paths when running under a supervisor.

An owner list may be `["*"]` to accept every owner on that exact host. JWT grants,
gateway denies, and upstream permissions still apply. A wildcard signing-key
ceiling requires a wildcard provider for that host; a wildcard provider can also
use narrower signing-key owner lists. Wildcard providers cannot overlap another
provider on the same host. The Compose image uses this opt-in wildcard mode so
no organization configuration is required.

```sh
gitvend validate --config gitvend.yaml
gitvend serve --config gitvend.yaml
```

The process runs in the foreground and writes operational logs to stderr. From another terminal:

```sh
curl --fail https://git-gateway.example:8443/healthz
```

Expected response: `ok`. This is a liveness check; it does not verify a JWT or contact GitHub. The agent's `ls-remote` command below verifies the Git path.

The remote URL has this structure:

```text
https://GATEWAY/PROVIDER_ALIAS/OWNER/REPOSITORY.git
https://git-gateway.example:8443/github/fooorg/project.git
```

The `github` segment is the configured provider alias. Permission strings use the configured upstream authority (`github.com`), not that alias or the gateway hostname. Repository permission patterns omit the `.git` suffix. Add more provider entries for distinct GitHub-compatible endpoints or owner/credential mappings; overlapping host/owner routes are rejected. Other forge APIs require an adapter.

### Running behind a TLS terminator

Set `allow_http: true` only for the protected HTTP listener behind the terminator, and bind it to the intended internal interface. This option makes the listener serve HTTP even if TLS files are present. Agents still use the public HTTPS address and its exact host/port in their credential helper.

Preserve the URL, `Authorization` and `Git-Protocol` headers, allow streaming request/response bodies, and align ingress body, header and timeout limits with gitvend. `allow_http_upstream` is a separate local-test option; upstream GitHub connections remain HTTPS. Neither option disables certificate verification for HTTPS.

## Issue an agent credential

On the trusted orchestrator, issue a short-lived JWT carrying the task's permissions:

```sh
gitvend sign \
  --key var/signing.key \
  --kid orchestrator-1 \
  --issuer orchestrator \
  --subject agent-47 \
  --audience gitvend \
  --ttl 15m \
  --permission 'github.com/fooorg/project#main:r' \
  --permission 'github.com/fooorg/project#agents/47/*:rw' \
  --permission 'github.com/fooorg/agent-47-*:c' \
  --permission 'github.com/fooorg/agent-47-*#agents/47/*:rw' \
  --output var/agent-47.jwt
```

Alternatively, save the [grant example](../examples/grant.json) locally and pass
`--grant grant.json`. The grant file is JSON and contains `v` and the `permissions` array. Permissions follow repository names, including future repositories with matching names; there are no repository-ID bindings. `--output` replaces the token file atomically with permissions `0600`; without it, `sign` writes the token to stdout. `keygen` refuses to overwrite existing key files.

JWTs use Ed25519 signatures (`alg=EdDSA`, `typ=gitvend+jwt`). Verification requires the configured issuer, key ID and audience plus subject, token ID, issued-at, not-before, expiry and grant version. Unknown fields, duplicate JSON keys, unsupported algorithms and malformed rules are rejected. The gateway needs no issued-token database and never contacts the issuer on a Git request.

The sample grant allows reading `main`, reading/writing `agents/47/*` branches, and creating private scratch repositories named `agent-47-*` with writable branches under the same prefix. It does not allow pushing `main`, deleting branches or creating tags. The sample server deny rule protects `main` and `master` even if a later JWT grants them writes.

Deliver `var/agent-47.jwt` to the agent through your orchestrator's secret mechanism, for example as `/run/secrets/gitvend.jwt`. The file must be readable by that agent. Gitvend does not deliver tokens to agents itself.

Refresh the injected file before expiry. Re-running the signing command with `--output` atomically replaces its output file; arrange the same replacement at the agent's token path. The credential helper reads the current file for each credential request, so Git remotes need no change. The default maximum lifetime is 15 minutes; a longer `--ttl` also requires a matching server-side `max_token_lifetime_seconds` setting.

A task's existing token remains usable until expiry plus configured clock tolerance even if the issuer stops renewing it. There is no immediate per-agent revocation list. Removing a signing key or adding a gateway-wide deny rule affects new requests after reload; an admitted transfer may finish within its deadline.

## Use gitvend as an agent

### Configure Git authentication

Run these commands inside the agent's own OS account or sandbox, with `gitvend` on `PATH`:

```sh
git config --global protocol.version 2
git config --global credential.https://git-gateway.example:8443.helper ''
git config --global --add credential.https://git-gateway.example:8443.helper \
  '!gitvend credential --host git-gateway.example:8443 --token-file /run/secrets/gitvend.jwt'
```

The empty entry resets inherited helpers for this host. The helper supplies username `git` and the JWT as the HTTPS Basic password only for the exact configured host and port. Use `git-gateway.example` in both settings if serving on standard HTTPS port 443 with no explicit port in the URL. The shell-style `!` helper invokes `gitvend` from `PATH`; Git appends its `get`, `store` or `erase` operation automatically. Store/erase are ignored because the orchestrator owns token replacement.

`--token-env VARIABLE_NAME` can replace `--token-file` if you inject the JWT into the agent's environment. Do not put the JWT in a clone URL. A custom Git client can use HTTP Basic directly, with the JWT as its password, and must request protocol v2 for fetch/discovery.

### Clone and push an assigned branch

```sh
# Confirm that the credential, route and upstream repository work.
git ls-remote --heads https://git-gateway.example:8443/github/fooorg/project.git

# Select main explicitly, even if the repository's default branch is hidden.
git clone --branch main https://git-gateway.example:8443/github/fooorg/project.git
git -C project switch -c agents/47/my-task

# After making and committing your changes, push an explicit destination.
git -C project push -u origin HEAD:refs/heads/agents/47/my-task
```

With the sample grant, discovery shows `main` and any existing `agents/47/*` branches. The push can create the assigned branch or update it. A push to `refs/heads/main` is denied. If one push contains any unauthorized ref update, gitvend rejects the whole request before forwarding its push commands or pack to GitHub. GitHub may independently reject permitted updates through its branch rules; use `git push --atomic` when you require all permitted updates to succeed together and the upstream supports it.

For an existing checkout, route its remote through the gateway:

```sh
git -C project remote set-url origin https://git-gateway.example:8443/github/fooorg/project.git
```

Changing a remote does not remove previously fetched objects or refs from that checkout. Use a fresh clone when you want its initial local refs to reflect the current discovery grant.

### Create a missing scratch repository on first push

The sample token also grants creation of `fooorg/agent-47-*`. Create a local repository with a branch the agent can write, then push it through the gateway:

```sh
git init -b agents/47/start agent-47-scratch
git -C agent-47-scratch config user.name 'Agent 47'
git -C agent-47-scratch config user.email 'agent-47@example.invalid'
git -C agent-47-scratch commit --allow-empty -m 'Initialize agent scratch repository'
git -C agent-47-scratch remote add origin \
  https://git-gateway.example:8443/github/fooorg/agent-47-scratch.git
git -C agent-47-scratch push -u origin HEAD:refs/heads/agents/47/start
```

Gitvend creates the missing private repository during push discovery, then forwards the authorized push. It creates no initial commit or `main` branch of its own. For a later clone, select `--branch agents/47/start` explicitly. A clone of a missing repository does not create it. Even `git push --dry-run` can create an empty repository; see [provisioning behavior](#provisioning-and-audit).

## Permission strings

```text
[!]host/namespace/repository[#ref-selector]:actions
```

| Action | Meaning |
| --- | --- |
| `r` | Read objects by hash and discover matching refs. |
| `w` | Create/update matching refs, including force updates. |
| `d` | Delete matching refs. |
| `c` | Create matching repositories using the provider's creation defaults; use without a ref selector. |

```text
github.com/fooorg/*:r
github.com/fooorg/blue*:rw
github.com/*:r
github.com/fooorg/red#(main|master|link):rw
!github.com/fooorg/*#(main|master):wd
```

Each rule is a separate `--permission` argument or an element in a grant's `permissions` array; do not combine rules into a comma-separated string. Quote rules in shell commands so glob and `!` characters reach gitvend unchanged.

| Rule | Use |
| --- | --- |
| `github.com/fooorg/project#main:r` | Discover main and allow repository hash reads. |
| `github.com/fooorg/project#agents/47/*:rw` | Read/create/update this agent's branches. Add `d` (`:rwd`) to allow deletion. |
| `github.com/fooorg/project#refs/tags/agent-47-*:rw` | Read/create/update matching tags explicitly. |
| `github.com/fooorg/agent-47-*:c` | Permit matching repository creation; also grant `rw` on at least one branch. |
| `!github.com/fooorg/*#(main\|master):wd` | Deny main/master writes and deletion across the organization. |

Repository `*` stays within one path segment; branch `*` can span `/`. `(a|b)` selects alternatives, not arbitrary regular expressions. `github.com/*` is the whole-host shorthand, still constrained by configured owners.

Matching allows combine; any matching deny wins. No `#` covers branches and tags; `#*` covers branches only. A `w` or `d` operation also requires read/discovery permission. `r` scoped to a branch hides other refs but deliberately does not block known-hash reads from the same repository. A broad read grant is not narrowed by adding a more specific grant.

See [the complete syntax](permission-syntax.md) for wildcard, alternative, escaping and deny semantics. Inspect a decision without making network calls:

```sh
gitvend explain \
  --permission 'github.com/fooorg/*:r' \
  --permission 'github.com/fooorg/blue*:w' \
  --permission '!github.com/fooorg/*#main:wd' \
  --repo github.com/fooorg/bluebird \
  --ref refs/heads/main \
  --action ref.update
```

The example returns `"allowed": false`. `explain` evaluates only the rules you pass; include applicable deny rules yourself. It does not load server configuration, verify a JWT, or check GitHub permissions. A valid explanation command exits successfully even for a denied decision; inspect `allowed`. A `repo.create` explanation evaluates the `c` permission only, not the additional branch-overlap or upstream checks.

## Provisioning and audit

Repository creation is opt-in twice: the provider must set `allow_creation: true` and the JWT must grant `c` plus an overlapping readable/writable branch. Matching deny rules still apply to both creation and branch writes.

Creation occurs during receive-pack discovery. Consequently, `git push --dry-run`, abandoned pushes and later branch-policy rejections may leave empty repositories. Clone/fetch never creates repositories. Direct receive-pack POSTs cannot create missing repositories. Created repositories are private by default and always uninitialized; the gateway never changes an existing repository's visibility, deletes it, or silently seeds `main`.

Concurrent creation is coordinated by the forge's repository-name uniqueness. Different gateway instances may both attempt creation; after a conflict or ambiguous response, gitvend looks up the name and checks that the resulting repository matches the configured creation visibility and requested owner/name. It never changes an existing repository's visibility. If the outcome cannot be confirmed, the request fails with 503; a later normal push discovery performs a fresh lookup. There are no background reconciliation jobs, creation quotas or stored attempts.

### Repository creation defaults

Each GitHub provider can specify its own `creation_defaults`, alongside its
upstream credentials and `allow_creation`:

```yaml
allow_creation: true
creation_defaults:
  visibility: private
  has_issues: false
  has_projects: false
  has_wiki: false
  has_pull_requests: false
```

Supported settings use GitHub's field names:

| Settings | Values and behavior |
| --- | --- |
| `visibility` | `private` (default) or `public`. |
| `has_issues`, `has_projects`, `has_wiki`, `has_pull_requests` | Optional booleans. An explicit `false` disables the feature; omission leaves GitHub's default. |
| `description`, `homepage` | Optional strings applied to newly created repositories. |
| `pull_request_creation_policy` | Optional `all` or `collaborators_only`. |
| `allow_squash_merge`, `allow_merge_commit`, `allow_rebase_merge` | Optional booleans. At least one merge method must remain available. |
| `allow_auto_merge`, `delete_branch_on_merge` | Optional booleans; GitHub account/organization restrictions still apply. |

Gitvend supplies `name` from the authorized repository and always sets
`auto_init: false`. Initialization templates and client-selected creation options
are not accepted. GitHub organization policies and upstream permissions can
reject settings; these errors fail provisioning rather than silently changing
requested options. See the [GitHub creation API](https://docs.github.com/en/rest/repos/repos#create-an-organization-repository).

Pull request availability and its creation policy use GitHub's
[repository update API](https://docs.github.com/en/rest/repos/repos#update-a-repository)
after creation or successful name reconciliation, before forwarding discovery
and the first push. The API credential must authorize these repository updates
as well as creation. A failed/unconfirmed update returns HTTP 502 and records
`configuration_failed`. The repository may already exist: inspect and complete
its settings before retrying. These are creation defaults, not ongoing policy
enforcement. An existing repository found by the initial lookup is left unchanged,
including on a later retry or after a gateway restart. Gitvend does not store
pending provisioning state or roll back repository creation.

Defaults belong to the upstream provider, not to a JWT signing key or JobDB
tenant. Different providers can use different tokens and defaults for distinct
organizations/users. Provider selection uses the URL alias; overlapping owners
on the same host are rejected. Repository-pattern credential routing within one
organization is not supported.

Permissions follow repository names. Deleting and recreating a repository under the same name leaves a matching JWT grant applicable to that name. Gitvend does not enroll repositories or pin their IDs.

### Audit logs

`gitvend serve` emits newline-delimited JSON audit records on **stdout** and operational logs on stderr. Collect stdout with your process supervisor or logging service. Gitvend keeps no audit database or outbox and has no `audit` command.

Each JSON record has an `audit` object containing request ID, issuer/subject, token ID, repository, operation and outcome when available. A request can emit an `admitted` event before contacting the upstream and a final outcome with the same `audit.id`. Creation events have a separate ID and an `audit.parent_id` linking them to the Git request's `X-Request-ID` response header. JWT strings, upstream tokens and pack contents are excluded.

For example, inspect an existing log export with `jq`:

```sh
jq -c 'select(.audit.operation == "git-receive-pack") | .audit' audit.jsonl
```

Push audit distinguishes `accepted`, `rejected`, `partial` and `unknown`; HTTP 200 alone is not success. Creation outcomes are `created`, `reconciled`, `configuration_failed`, `rejected` or `unknown` and do not claim that a subsequent push succeeded. A crash can leave an admission with no final record. Log delivery is best-effort, with retention and durability handled by your logging infrastructure. Inspect the remote refs before retrying an interrupted push; gitvend never retries a push automatically.

### Multiple instances

Run any number of instances behind the same HTTPS endpoint with matching configuration, trusted keys and credentials. No shared disk, database, distributed lock or sticky session is required. Configuration/key rotations must reach each instance; a reload on one instance does not update others. `max_concurrent` and request limits apply per instance. If you need fleet-wide rate limits or creation budgets, enforce them outside gitvend. A metrics export endpoint is not implemented.

## Configuration and limits

Run the service under a supervisor with a consistent working directory and readable configuration/key/credential files. The running gateway can use a read-only filesystem; operator commands such as `keygen` and `sign --output` still write their explicitly requested files. `SIGTERM` or Ctrl-C starts graceful shutdown with a 10-second drain period; transfers still running afterward are closed.

Send `SIGHUP` to atomically reload public keys, issuer ceilings, upstream token files, deny rules and limits. A failed reload preserves the last valid configuration. Changes to the listener or TLS paths require restart. Replacing an environment variable requires restarting the process. Config reload does not rewrite credentials already in use by an admitted operation.

For signing-key rotation, add the new public key under a new `id`, reload, and issue tokens with that `--kid`. Keep the old key configured until its tokens have expired, including clock tolerance, if they should remain valid; then remove it and reload. To rotate an upstream file token, replace that file and reload; the gateway reads upstream credentials at startup/reload, unlike the agent helper, which reads its JWT for each credential request.

Important defaults:

| Setting | Default |
| --- | --- |
| `max_token_bytes` | 4,096 serialized JWT bytes; configurable up to 32,768 |
| `max_token_lifetime_seconds` | 900 |
| `clock_skew_seconds` | 30 |
| `max_control_bytes` | 4 MiB |
| `max_pack_bytes` | 1 GiB incoming encoded and decoded request body limits |
| `max_concurrent` | 64 active Git requests |
| `request_timeout_seconds` | 1,800 |

The HTTP server accepts up to 64 KiB of headers. Basic authentication expands a JWT by roughly one-third, so ingress limits must accommodate the configured token budget too. Use `sign --max-token-bytes` with the same budget as the gateway. Oversized grants are rejected, never truncated or broadened.

Incoming packs are streamed after their command prefix passes authorization. Pack contents are not inspected for file/path rules or commit ancestry.

Ordinary clone/fetch/push requests need only the upstream Git endpoint. REST lookups are used during push discovery when both the configuration and JWT permit automatic creation. Those API calls share the upstream credential's rate limit; gitvend does not coordinate rate limits across instances.

## Troubleshooting

Start with `gitvend version`, `/healthz`, and `git ls-remote --heads` as shown above. Use the HTTP `X-Request-ID` for authenticated Git requests to correlate a failure with the collected audit logs. Avoid sharing raw credentials or full authorization headers when collecting diagnostics.

| Symptom | What to check |
| --- | --- |
| Connection refused or TLS certificate error | Confirm the listener interface/port, DNS, certificate hostname and trust chain. The template binds loopback; external agents need a reachable listener or TLS terminator. |
| Git prompts for a password; helper returns no credential | Confirm `gitvend` is on the agent's `PATH`, the JWT file is readable, and the helper's host **and port** match the remote. Configure the helper in that agent's account. |
| HTTP 401 / invalid or expired JWT | Refresh the JWT; check issuer, `kid`, audience, clock, lifetime and byte limits against gateway configuration. Agents use their JWT, not the upstream GitHub token. |
| `Git protocol v2 required` | Set `protocol.version=2`; ensure an ingress proxy preserves the `Git-Protocol` header. Pushes still use standard receive-pack. |
| HTTP 403 / `push denied for ...` | Inspect the exact destination ref, matching `r` plus `w`/`d` grants, issuer/owner limits and gateway denies. The sample denies writes to main/master. |
| No refs shown; clone cannot find main or remote HEAD | The requested branch may be absent or hidden. Use an explicitly permitted branch with `--branch`; new scratch repos may have only `agents/47/start`. |
| HTTP 404 / unsupported route or missing repository | Use `/alias/owner/repo.git`, check allowed owners, and verify the upstream identity can see the repository. Only authorized push discovery can create a missing repo. |
| Missing repo is not created | Check `allow_creation`, `c`, overlapping branch `rw`, owner limits and upstream organization permissions. Check the audit logs for an unconfirmed create attempt. |
| HTTP 429 / gateway busy | The concurrent-request limit is reached. Wait for active requests to finish and retry. |
| HTTP 409 / creation visibility violation | A creation attempt resolved to unexpected visibility. Investigate the upstream name/visibility; gitvend will not alter it automatically. |
| HTTP 502 / configuration incomplete | The repository exists but its requested pull request settings could not be confirmed. Inspect and complete the settings before retrying. |
| HTTP 502 / upstream request refused or lookup failed | Check the upstream token, Git/API base URLs and forge availability/rate limits. A gateway JWT cannot overcome upstream restrictions. |
| HTTP 503 / repository creation unconfirmed | The create attempt and follow-up lookup could not confirm success. Check upstream access/availability, then retry normal push discovery. |
| HTTP 431 or large token rejected at ingress | Align ingress header limits, server `max_token_bytes` and signing `--max-token-bytes`; Basic authentication expands the token. |
| Push disconnects or audit outcome is `unknown` | Fetch or inspect the permitted remote ref before deciding whether to retry; some or all updates may already have reached GitHub. |
| npm-installed command reports a missing binary | Check whether install scripts were disabled and whether release downloads were reachable; after fixing that, run `npm rebuild @colony2/gitvend`. |

When upgrading an earlier checkout, remove `state_file`, `creates_per_subject_per_day` and `creates_per_owner_per_day` from configuration. Remove `bindings` from grant files and reissue any JWTs containing that field. Unknown fields are rejected. Old database files are no longer read by the gateway.

## CLI reference

Run `gitvend --help` for a setup walkthrough, or use `--help` on any command.
The CLI supports shell completion and accepts both standard `--flag` options and
legacy single-dash long flags. For credential helpers, Git appends the final operation.

| Command | Purpose / useful flags |
| --- | --- |
| `gitvend version` | Show the release version or development build identity. |
| `gitvend serve --config gitvend.yaml` | Start the gateway. |
| `gitvend validate --config gitvend.yaml` | Validate local config, public keys and upstream credential references without starting the server. |
| `gitvend keygen --private signing.key --public signing.pub` | Generate a new issuer key pair without overwriting existing files. Add `--if-missing` to validate/reuse persistent keys or recover a missing public key. Parent directories must exist. |
| `gitvend sign` | Issue a JWT; requires `--key`, `--kid`, `--issuer`, `--subject` and a grant. Use repeated `--permission` **or** `--grant`, not both; `--output` writes an atomic token file. |
| `gitvend credential` | Git helper; specify `--host` and exactly one of `--token-file` or `--token-env`, followed by `get`, `store` or `erase`. |
| `gitvend explain` | Explain explicit `--permission` rules for a `--repo`, optional `--ref`, and `--action`. Ref values are fully qualified, such as `refs/heads/main`. |

`explain` actions are `repo.read`, `repo.create`, `ref.discover`, `ref.create`, `ref.update` and `ref.delete`. The default is `ref.update`.

## Compatibility

Supported object format is SHA-1. SSH, Git LFS, Git protocol v0/v1 fetch, signed push certificates, push options, named shallow exclusions, ref-in-want, offloaded pack/bundle URLs and provider-managed ref namespaces are rejected or not advertised. Branch writes can include workflow files; CI execution and secrets remain governed by the forge's configuration. GitHub branch rules continue to apply to the shared upstream identity.

Use a disposable repository to confirm your upstream token, organization creation
policy, workflow permissions and GitHub Enterprise version before rolling out to
workers. Gitvend's configuration cannot grant access that GitHub rejects.

See the [developer guide](development.md) for source builds, testing and release
maintenance, or return to the [overview](../README.md).
