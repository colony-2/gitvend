package jobdbprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	gitconfig "github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/policy"
	"github.com/colony-2/jobdb/pkg/jobdb"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// BaseSecretName requests the configured tenant base permissions.
	BaseSecretName = "gitvend_base_token"
	// CellSecretName requests base permissions plus rules narrowed to the authorized target cell.
	CellSecretName = "gitvend_cell_token"
)

var _ jobdb.SecretProvider = (*Provider)(nil)

func (p *Provider) ResolveSecrets(ctx context.Context, r jobdb.SecretResolveRequest) (jobdb.SecretResolveResult, error) {
	out := jobdb.SecretResolveResult{Secrets: map[string]jobdb.SecretValue{}}
	if err := ctx.Err(); err != nil {
		return jobdb.SecretResolveResult{}, err
	}
	t, ok := p.tenants[r.TenantID]
	if !ok {
		if slices.Contains(r.Names, CellSecretName) {
			cellTokenUnavailable(ctx, "tenant is not configured")
		}
		return out, nil
	}
	if len(t.principals) > 0 && (r.Principal == nil || !t.principals[*r.Principal]) {
		if slices.Contains(r.Names, CellSecretName) {
			cellTokenUnavailable(ctx, "principal is not authorized for this tenant")
		}
		return out, nil
	}
	for _, name := range r.Names {
		if err := ctx.Err(); err != nil {
			return jobdb.SecretResolveResult{}, err
		}
		if name != BaseSecretName && name != CellSecretName {
			continue
		}
		if _, issued := out.Secrets[name]; issued {
			continue
		}
		permissions := append([]string(nil), t.base...)
		if name == CellSecretName {
			// Only the broker-verified cell establishes the job's repository.
			// Application metadata must neither override it nor supply a fallback.
			if r.Lease.Cell.CellID == "" {
				cellTokenUnavailable(ctx, "verified Lease.Cell.CellID is missing; use a JobDB host with cell context support")
				continue
			}
			if r.Lease.Cell.CellRepo == "" {
				cellTokenUnavailable(ctx, "verified Lease.Cell.CellRepo is missing")
				continue
			}
			repo, ok := cellRepository(r.Lease.Cell.CellRepo)
			if !ok {
				cellTokenUnavailable(ctx, "verified Lease.Cell.CellRepo is not a supported repository locator")
				continue
			}
			if t.target == nil {
				cellTokenUnavailable(ctx, "no target_permissions configured for this tenant")
				continue
			}
			// Retain actions, ref selectors and denies, narrowing only the repository.
			matchedAllow := false
			for _, rule := range t.target.Rules {
				if narrowed, matches := rule.ForRepository(repo); matches {
					permissions = append(permissions, narrowed)
					matchedAllow = matchedAllow || !rule.Deny
				}
			}
			if !matchedAllow {
				cellTokenUnavailable(ctx, "no target_permissions allow rule matches the verified cell repository")
				continue
			}
		}
		if len(permissions) == 0 {
			continue
		}
		if r.JobID == "" || r.Lease.LeaseID == "" || r.Lease.WorkerID == "" ||
			r.Lease.LeaseExpiresAt.IsZero() || r.Lease.AuthorizedNotAfter.IsZero() {
			return jobdb.SecretResolveResult{}, jobdb.ErrSecretResolutionFailed
		}
		value, err := p.issue(r, permissions)
		if err != nil {
			return jobdb.SecretResolveResult{}, err
		}
		out.Secrets[name] = value
	}
	if err := ctx.Err(); err != nil {
		return jobdb.SecretResolveResult{}, err
	}
	return out, nil
}

// JobDB's result has no per-name diagnostics and its SDK redacts error details.
// Keep omissions independent of other secrets and report only fixed messages on
// stderr, which the JobDB host forwards to its provider log.
func cellTokenUnavailable(ctx context.Context, reason string) {
	slog.WarnContext(ctx, CellSecretName+" unavailable: "+reason)
}

func (p *Provider) issue(r jobdb.SecretResolveRequest, permissions []string) (jobdb.SecretValue, error) {
	now := p.now().UTC()
	issuedAt := now.Truncate(time.Second)
	deadline := r.Lease.AuthorizedNotAfter
	if r.Lease.LeaseExpiresAt.Before(deadline) {
		deadline = r.Lease.LeaseExpiresAt
	}
	allowance := time.Duration(p.config.GatewayLeewaySeconds+p.config.ClockMarginSeconds) * time.Second
	expiry := deadline.Add(-allowance).Truncate(time.Second)
	if limit := issuedAt.Add(time.Duration(p.config.MaxLifetimeSeconds) * time.Second); limit.Before(expiry) {
		expiry = limit
	}
	if !expiry.After(now) {
		return jobdb.SecretValue{}, jobdb.ErrSecretsUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return jobdb.SecretValue{}, jobdb.ErrSecretResolutionFailed
	}
	// Bind the audit subject to the tenant, job and lease attempt without exceeding
	// Gitvend's 256-byte subject limit. These are not additional gateway claims.
	identity, _ := json.Marshal([]any{r.TenantID, r.JobID, r.Lease.LeaseID, r.Lease.WorkerID, r.Principal})
	subject := sha256.Sum256(identity)
	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: p.config.Issuer, Audience: jwt.ClaimStrings{p.config.Audience},
			Subject: "jobdb:" + hex.EncodeToString(subject[:]), ID: hex.EncodeToString(id[:]),
			IssuedAt: jwt.NewNumericDate(issuedAt), NotBefore: jwt.NewNumericDate(issuedAt), ExpiresAt: jwt.NewNumericDate(expiry),
		},
		Grant: auth.Grant{Version: 1, Permissions: permissions}, PolicyRevision: p.config.PolicyRevision,
	}
	token, err := auth.Sign(claims, p.key, p.config.KeyID, p.config.MaxTokenBytes)
	if err != nil {
		return jobdb.SecretValue{}, jobdb.ErrSecretResolutionFailed
	}
	return jobdb.SecretValue{Value: token, ExpiresAt: &expiry, LeaseBound: true}, nil
}

func cellRepository(source string) (policy.Repository, bool) {
	if strings.HasPrefix(source, "https://") {
		u, err := url.Parse(source)
		if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(source, "#") || u.RawPath != "" || u.Opaque != "" {
			return policy.Repository{}, false
		}
		source = u.Host + u.Path
	}
	host, path, ok := strings.Cut(source, "/")
	path = strings.TrimSuffix(path, ".git")
	owner, repo, hasOwner := strings.Cut(path, "/")
	if !ok || !hasOwner || !policy.ValidHost(host) || !gitconfig.ValidName(owner) || !gitconfig.ValidName(repo) {
		return policy.Repository{}, false
	}
	return policy.Repository{Host: host, Path: strings.ToLower(owner + "/" + repo), FoldCase: true}, true
}
