// Package audit emits structured events to an operator-provided logger.
// Events are not persisted or queued by the gateway.
package audit

import (
	"log/slog"
	"time"
)

type Event struct {
	ID                string    `json:"id"`
	ParentID          string    `json:"parent_id,omitempty"`
	Time              time.Time `json:"time"`
	Issuer            string    `json:"issuer,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	TokenID           string    `json:"token_id,omitempty"`
	PolicyRevision    string    `json:"policy_revision,omitempty"`
	ConfigRevision    string    `json:"config_revision,omitempty"`
	Repository        string    `json:"repository,omitempty"`
	Operation         string    `json:"operation"`
	Outcome           string    `json:"outcome"`
	Reason            string    `json:"reason,omitempty"`
	Updates           any       `json:"updates,omitempty"`
	UpstreamRequestID string    `json:"upstream_request_id,omitempty"`
	Details           any       `json:"details,omitempty"`
}

func (e Event) Log(logger *slog.Logger) {
	logger.Info("audit", "audit", e)
}
