package jobdbprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	gitconfig "github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/jsonutil"
	"github.com/colony-2/gitvend/internal/policy"
	"github.com/colony-2/jobdb/pkg/jobdb"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// ReadSecretName requests the configured tenant read permissions.
	ReadSecretName = "gitvend_read_token"
	// CellSecretName requests tenant reads plus writes to the authorized target cell.
	CellSecretName = "gitvend_cell_token"
)

var _ jobdb.SecretProvider = (*Provider)(nil)

func (p *Provider) ResolveSecrets(ctx context.Context, r jobdb.SecretResolveRequest) (jobdb.SecretResolveResult, error) {
	out := jobdb.SecretResolveResult{Secrets: map[string]jobdb.SecretValue{}}
	if err := ctx.Err(); err != nil {
		return jobdb.SecretResolveResult{}, err
	}
	t, ok := p.tenants[r.TenantID]
	if !ok || len(t.principals) > 0 && (r.Principal == nil || !t.principals[*r.Principal]) {
		return out, nil
	}
	for _, name := range r.Names {
		if err := ctx.Err(); err != nil {
			return jobdb.SecretResolveResult{}, err
		}
		if name != ReadSecretName && name != CellSecretName {
			continue
		}
		if _, issued := out.Secrets[name]; issued {
			continue
		}
		permissions := append([]string(nil), t.reads...)
		if name == CellSecretName {
			repo, ok := cellRepository(r.AppMetadata, p.config.CellMetadataField)
			if !ok || t.writes == nil || !t.writes.Read(repo) {
				continue
			}
			// Only the exact, normalized repository enters the JWT, never a metadata pattern.
			permissions = append(permissions, repo.Host+"/"+repo.Path+":rw")
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

func cellRepository(metadata json.RawMessage, field string) (policy.Repository, bool) {
	var fields map[string]json.RawMessage
	// Other metadata belongs to the application; accept it while rejecting duplicate keys.
	if len(metadata) > 1<<20 || jsonutil.Decode(metadata, &fields) != nil {
		return policy.Repository{}, false
	}
	var source string
	if json.Unmarshal(fields[field], &source) != nil {
		return policy.Repository{}, false
	}
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
