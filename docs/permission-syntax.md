# JWT permission syntax, version 1

Status: implemented version 1. This defines the compact permission strings used by the [Git gateway design](git-proxy-design.md). Permissions are signed inside the JWT and evaluated locally; no permission-name or role lookup is required.

## Shape

```text
[!]host/namespace/repository[#ref-selector]:actions
```

Examples:

```text
github.com/fooorg/*:r
github.com/fooorg/blue*:rw
github.com/*:r
github.com/fooorg/red#(main|master|link):rw
github.com/fooorg/red#agents/agent-47/*:rw
github.com/fooorg/red#refs/tags/v*:r
github.com/fooorg/agent-47-*:c
!github.com/fooorg/*#(main|master):wd
```

The JWT contains an array of strings, not a comma-separated string. Each string is one rule. The optional leading `!` makes a deny rule; otherwise it is an allow rule. Rule order has no meaning.

## Actions

| Letter | Permission |
| --- | --- |
| `r` | Read objects by hash in the matching repository and discover/resolve matching refs. A ref selector restricts discovery, not hash reads. |
| `w` | Create or update matching refs, including history rewrites, subject to upstream restrictions. Does not delete refs or create repositories. |
| `d` | Delete matching refs. Does not delete the repository. |
| `c` | Create matching repositories using the route's server-controlled private creation profile. Does not itself grant reads or ref writes. |

Letters may be combined, such as `rw`, `rwd`, or `rwc`. Reject empty, duplicate or unknown action letters; issuers serialize in `rwdc` order. `w` and `d` do not imply `r`: a write also requires effective read/discovery permission on its destination, possibly from another rule. This permits a broad `:r` plus a narrow `:w` without repeating read grants. No separate force-push letter is claimed: distinguishing history rewrites from fast-forwards remains outside the initial streaming gate.

`c` is valid only without a `#ref-selector`, including in combinations and denies. Repository creation has no branch identity. Actual create-on-discovery additionally requires repository read permission and an effective `r`/`w` overlap for at least one possible branch. Creation never grants authority to write other refs.

## Repository matching

The host is an exact, lowercase configured Git authority, optionally with a configured port. No host wildcards, scheme, userinfo, query or client-chosen server URL. For example, `github.com` maps to the configured GitHub provider, API endpoint, credential and allowed owners. Multiple credential routes must be resolved deterministically by host/namespace; ambiguous routes fail configuration validation. A host-wide grant cannot enable an unconfigured owner or exceed its issuer's local authority ceiling.

Repository paths are canonical `namespace/repository` names, without the transport `.git` suffix. GitHub paths have an owner and a repository; later adapters may allow nested namespaces. Match against the adapter's canonical identity, never against the raw incoming URL. Hostnames are case-insensitive; repository case handling follows the adapter; branch and tag names are case-sensitive. Redirects and aliases are not permission matches.

| Pattern | Meaning |
| --- | --- |
| `fooorg/red` | That exact repository. |
| `fooorg/*` | Every repository directly in `fooorg`. |
| `fooorg/blue*` | Repositories directly in `fooorg` whose names begin with `blue`, including `blue` itself. |
| `*/red` | Repository `red` in any one-level namespace. |
| `fooorg/**` | Repositories in `fooorg` and recursively nested namespaces, for adapters that support them. |
| `*` immediately after the host | Whole-host shorthand: all canonical repository paths on that configured host, at any namespace depth. Equivalent to `**` in this position. |

In ordinary path segments, `*` matches zero or more characters but never `/`. A standalone `**` path segment spans namespace levels; `fooorg/**/red` can match `fooorg/red` and `fooorg/team/red`. `**` is not allowed embedded in a segment. Every matched target must still be a valid repository identity; a glob never names a namespace itself as a repository.

The whole-host `host/*` form is an explicit shorthand, not a general rule that ordinary path stars cross slashes. It supports the requested `github.com/*:r` spelling without broadening `github.com/fooorg/*` to unrelated namespaces.

## Ref selectors

| Selector | Meaning |
| --- | --- |
| No `#` | Whole repository: all supported branches and tags for `r`, `w` and `d`; repository-level scope for `c`. |
| `#main` | Exactly `refs/heads/main`. |
| `#(main|master|link)` | Those three branch names. |
| `#agents/agent-47/*` | Branches with that prefix, including nested suffixes. |
| `#*` | All branches, not tags. |
| `#refs/heads/release/*` | Explicit fully qualified branch selector. |
| `#refs/tags/v*` | Tags whose names begin with `v`. |

Without an explicit `refs/heads/` or `refs/tags/` prefix, the selector names a branch. Ref wildcards match the **whole branch or tag name**, so `*` may span `/` here. `**` has no additional meaning in ref selectors and is rejected to avoid competing spellings. This intentionally differs from namespace path segments: the slash in a branch name is part of the branch name, not a repository boundary.

Only branch and tag namespaces are supported initially. Explicit selectors beginning `refs/` must use a literal supported namespace prefix; `#refs/*` and selectors for provider-managed refs are invalid. To match a branch literally named `refs/tags/example`, use `#refs/heads/refs/tags/example`.

An unrestricted repository `:rw` therefore includes tag creation/update. Issuers that intend branch-only writes must use `#*:rw`, and branch-restricted work should use a narrower selector. Repository-wide grants deliberately opt into broader scope; tags are otherwise hidden and unwritable without a matching grant. `HEAD` is handled by the gateway's symbolic-ref visibility rules, not as a separate writable ref.

## Alternatives and literal characters

`(a|b|c)` means a choice of glob fragments, not a regular expression. It can appear inside a namespace/repository segment or ref selector. For example, `(blue|green)*` and `#(main|release/*)` are valid. Repository alternatives cannot contain `/`; use a separate rule for different path structures. Ref alternatives may contain `/`.

All matches cover the entire canonical field. `red` does not match `infra-red`; `main` does not match `main-old`; `.` is literal. There are no regex operators, character classes, nested groups or implicit substring matches. Reject empty alternatives, unmatched parentheses, unescaped bare `|`, `?`, `[` or `]`, and trailing escapes.

Backslash escapes grammar characters for literal matching, including `(`, `)`, `|`, `#`, `:`, `!` and backslash itself. Parse delimiters while respecting escapes; use the action-separating colon after the resource/ref portion, not a colon in a host port. JSON must itself escape backslashes: a selector for a branch literally named `topic(test)` is encoded as `"...#topic\\(test\\):r"`. Escaping does not legalize characters prohibited by the forge or Git. Do not percent-decode permission strings or interpret them as URLs.

## Combining rules

For each internal action, allow if at least one matching allow grants it and no matching deny removes it. Default deny. Specificity and ordering do not override a deny. Apply configured issuer/host/owner limits and gateway hard restrictions in addition; upstream permissions remain a final independent restriction.

| Internal action | Allow condition | Deny condition |
| --- | --- | --- |
| `repo.read` | Any repository-matching `r` rule, with or without a ref selector. | A repository-matching `r` deny **without** a ref selector. |
| `ref.discover` | A repository/ref-matching `r` allow. | A repository/ref-matching `r` deny. |
| `ref.create`, `ref.update` | A repository/ref-matching `w` allow. | A repository/ref-matching `w` deny. |
| `ref.delete` | A repository/ref-matching `d` allow. | A repository/ref-matching `d` deny. |
| `repo.create` | A repository-matching `c` allow. | A repository-matching `c` deny. |

Reading a named ref requires both `repo.read` and `ref.discover`. A ref mutation requires those two plus the corresponding write action. An allowed direct hash fetch only needs `repo.read`. A repository-wide `!…:r` consequently blocks all ordinary Git use of that repository, including writes that depend on read access. A branch-scoped `!…#secret/*:r` hides matching refs and blocks writes to them, but **does not** prevent fetching their objects by known hash. That is the previously selected read model, not a parser exception.

Examples of overlap:

- `github.com/fooorg/*:r` plus `github.com/fooorg/blue*:w`: discover all refs throughout the organization; create/update refs only in `blue*` repositories.
- `github.com/fooorg/red#main:r` plus `github.com/fooorg/red#agents/47/*:rw`: discover main and this agent's branches; only the agent branches are writable; hash reads remain repository-wide.
- `github.com/*:r` plus `github.com/fooorg/red#main:rw`: all configured GitHub repositories remain readable/discoverable. The narrower rule adds main writes; it does not narrow the broad read grant.
- `github.com/fooorg/*:rwd` plus `!github.com/fooorg/*#(main|master):wd`: keep those branches readable while preventing creation, updates and deletion, even if another allow grants them.

Wildcard grants are evaluated against the current repository/ref name at request time. They intentionally cover future matching repositories and branches, subject to local provider access. Existing enrolled repositories can still have stable-ID bindings in gateway metadata or optional signed `bindings`; a name pattern does not override such a binding. If exact identity pinning is required without gateway enrollment, the issuer must include the binding, at a token-size cost.

## JWT example

The following is the custom claim fragment; the full token also requires the identity, audience, lifetime and signature fields from the main design:

```json
{
  "grant": {
    "v": 1,
    "permissions": [
      "github.com/fooorg/red#main:r",
      "github.com/fooorg/red#agents/47/*:rw",
      "github.com/fooorg/agent-47-*:rc",
      "github.com/fooorg/agent-47-*#agents/47/*:rw",
      "!github.com/fooorg/*#(main|master):wd"
    ]
  }
}
```

This can read main, discover/write the agent's branches, and provision matching scratch repositories. Creation uses the route's private profile. The `rc` rule also deliberately grants all-ref discovery in those scratch repositories; remove `r` there and put it only on selected branches if narrower discovery is desired.

## Implementation and acceptance

Compile the signed strings into an immutable matcher after JWT verification and schema validation. Use a dedicated lexer/parser and bounded glob/alternative automata; do not feed raw token patterns into a regex engine or shell, and do not expand alternatives into an unbounded Cartesian product. Bound token bytes, rule count, pattern length and group count. Cache compiled grants by verified token digest, never just `sub` or a client-chosen `jti`, with expiry and relevant local configuration revision in the cache validity conditions.

Derive internal action checks from the table above. Apply the same canonicalization and matcher to ref discovery, direct receive-pack commands and provisioning. Creation eligibility is a nonempty language intersection: permitted branch `r` and `w` patterns minus denies must overlap. Compute that with bounded automata; do not sample candidate branch names or ignore denies. If computation exceeds configured complexity bounds, reject the grant/creation eligibility with a clear error.

Add a policy-explanation command for issuer/operator use that accepts a grant and concrete repository/ref/action and returns matching allows/denies and the decision. It should also flag obviously broad repository or host grants that make narrower grants redundant, without changing their meaning.

Acceptance cases must cover whole-host shorthand, segment boundaries, nested namespaces, branch slashes, alternatives, escapes, case rules, tags versus branches, overlapping grants/denies, denied branch hash fetches, unknown syntax, duplicate action letters, future matching names, stable-ID bindings and creation eligibility. Reject a malformed rule by rejecting the entire JWT grant, never by silently dropping that rule.
