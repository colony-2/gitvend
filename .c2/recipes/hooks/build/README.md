# Gitvend build verification

`verify.yaml` implements the shared `c2.build-hook/v1` contract. Its Node 22+
helper verifies the managed checkout identity, runs the five approved commands,
and exports `result.json` plus `evidence.json`. Evidence includes complete command
stdout/stderr, exit and timeout metadata, tool versions, coverage omissions, and
pre/post content hashes and index entries. Export failures block the operation.

CI selection baseline: `ea025082843ef5f3163787a4b134f40c78725e96`.
`test.yml` supplies `make check`, `make fuzz`, `make build` and
`npm test --prefix npm/gitvend`; `release.yaml` supplies `go mod tidy -diff`.
The current host is tested. Compose, other host/platform runs, release packaging,
signing, publication and deployment remain outside the hook's coverage.

Preexisting requirements: Go matching go.mod, Make, Git with git-http-backend,
C compiler/race support, Node/npm, tar, writable temporary/cache storage and local
networking/subprocess support. Module downloads may retrieve dependencies; Go
self-provisioning is disabled. No production credentials are needed.

Go verbose output exposes test skips. A fresh owned temporary Go cache forces
actual execution without test-only flags leaking into vet. The cache is removed
after checks. Architecture overrides and inherited Go/Make flags are cleared;
race support stays enabled. Timeout limits are 20 minutes for check and 10 minutes
each for the other commands. Timeouts terminate the owned process group.

Run runner integration tests without Go or production credentials:

```sh
node --test .c2/recipes/hooks/build/verify.test.mjs
c2j test run --file .c2/recipes/hooks/build/tests/verify.test.yaml --strict
```

The runner tests use disposable clones and controlled executable fixtures. They
do not prove application coverage. The recipe suite tests output/reference
compatibility and operation-error propagation using mocked operations.

To execute real checks manually, provide an existing operation output directory:

```sh
WORKTREE="$PWD" DIRECTORY=. CANDIDATE="$(git rev-parse HEAD)" OUTBOX=/path/to/evidence \
  node .c2/recipes/hooks/build/verify.mjs
```

Read `status` in result.json: an ordinary failed verification finalizes artifacts
and exits zero so the recipe can export them; finalization errors exit nonzero.
The shared build wrapper consumes the status. The helper never resets, checks
out, stages, commits or restores the managed candidate.

The hook prepares its own child-process environment. It prefers Go on PATH; when
absent, it probes already installed native Go executables in conventional Go/Nix
locations and records the selected installation and version probe in evidence.
It never installs a toolchain. If none is available, verification still fails.
For local Git fixture isolation, it appends an empty credential.helper entry to
process-local Git configuration, preserving other entries and allowing fixtures'
later command-line helpers. No user/repository configuration files are changed.
These steps make automated execution equivalent to the disclosed manual run;
manual PATH or credential-helper overrides are no longer necessary here.
