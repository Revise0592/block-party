package playit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The playit.gg API, as the official agent uses it (playit-cloud/playit-agent,
// packages/api_client): every call is a POST with a JSON body, signed with
// "Authorization: Agent-Key <secret>", and answered with
// {"status": "success" | "fail" | "error", "data": ...}.

// DefaultAPI is playit.gg's API.
const DefaultAPI = "https://api.playit.gg"

// APIError is an answer other than success. Code is playit's name for the
// failure ("RequiresPlayitPremium", "AgentVersionTooOld", "auth", ...).
type APIError struct {
	Path    string
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("playit.gg %s: %s (%s)", e.Path, e.Code, e.Message)
	}
	return fmt.Sprintf("playit.gg %s: %s", e.Path, e.Code)
}

// IsCode reports whether err is a playit answer with that code.
func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

type client struct {
	base   string
	secret string // empty for the claim calls
	http   *http.Client
}

func (c *client) call(ctx context.Context, path string, req, res any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if c.secret != "" {
		r.Header.Set("Authorization", "Agent-Key "+strings.TrimSpace(c.secret))
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return fmt.Errorf("couldn't reach playit.gg: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return &APIError{Path: path, Code: "TooManyRequests", Message: "asked too often; trying again shortly"}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("couldn't reach playit.gg: %w", err)
	}
	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return &APIError{Path: path, Code: fmt.Sprintf("HTTP %d", resp.StatusCode), Message: "an answer that isn't JSON"}
	}
	switch env.Status {
	case "success":
		if res == nil {
			return nil
		}
		if err := json.Unmarshal(env.Data, res); err != nil {
			return &APIError{Path: path, Code: "BadAnswer", Message: err.Error()}
		}
		return nil
	case "fail":
		// The data is the name of the failure: "RequiresPlayitPremium".
		var code string
		if json.Unmarshal(env.Data, &code) != nil {
			code = strings.Trim(string(env.Data), `"`)
		}
		return &APIError{Path: path, Code: code}
	default:
		// {"type": "auth", "message": ...}; the message may be a string or
		// an object.
		var e struct {
			Type    string          `json:"type"`
			Message json.RawMessage `json:"message"`
		}
		_ = json.Unmarshal(env.Data, &e)
		msg := strings.Trim(string(e.Message), `"`)
		if e.Type == "" {
			e.Type = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return &APIError{Path: path, Code: e.Type, Message: msg}
	}
}

// runData is the agent's own record.
type runData struct {
	AgentID       string `json:"agent_id"`
	AccountStatus string `json:"account_status"` // "ready", "guest", "email-not-verified", ...
}

func (c *client) runData(ctx context.Context) (runData, error) {
	var v runData
	err := c.call(ctx, "/agents/rundata", struct{}{}, &v)
	return v, err
}

// tunnel is one of the account's tunnels.
type tunnel struct {
	ID         string  `json:"id"`
	Name       *string `json:"name"`
	TunnelType *string `json:"tunnel_type"`
	PortType   string  `json:"port_type"` // "tcp", "udp" or "both"
	Active     bool    `json:"active"`    // enabled
	Alloc      struct {
		Status string `json:"status"` // "pending", "disabled" or "allocated"
		Data   struct {
			AssignedDomain string `json:"assigned_domain"`
			PortStart      int    `json:"port_start"`
			Reason         string `json:"reason"` // when disabled
		} `json:"data"`
	} `json:"alloc"`
	Origin *struct {
		Type string `json:"type"`
		Data struct {
			AgentID   string `json:"agent_id"`
			LocalIP   string `json:"local_ip"`
			LocalPort *int   `json:"local_port"`
		} `json:"data"`
	} `json:"origin"`
	DisabledReason *string `json:"disabled_reason"`
}

func (t tunnel) name() string {
	if t.Name == nil {
		return ""
	}
	return *t.Name
}

type portUsage struct {
	Allowed int `json:"allowed"`
	Claimed int `json:"claimed"`
}

type tunnelList struct {
	Tunnels []tunnel  `json:"tunnels"`
	TCP     portUsage `json:"tcp_alloc"`
	UDP     portUsage `json:"udp_alloc"`
}

func (c *client) listTunnels(ctx context.Context) (tunnelList, error) {
	var v tunnelList
	err := c.call(ctx, "/tunnels/list", map[string]any{"tunnel_id": nil, "agent_id": nil}, &v)
	return v, err
}

type newTunnel struct {
	Name       string
	TunnelType string // "" for a plain one
	PortType   string // "tcp" or "udp"
	AgentID    string
	LocalIP    string
	LocalPort  int
}

func (c *client) createTunnel(ctx context.Context, t newTunnel) (string, error) {
	var tt any
	if t.TunnelType != "" {
		tt = t.TunnelType
	}
	req := map[string]any{
		"name":        t.Name,
		"tunnel_type": tt,
		"port_type":   t.PortType,
		"port_count":  1,
		"origin": map[string]any{
			"type": "agent",
			"data": map[string]any{"agent_id": t.AgentID, "local_ip": t.LocalIP, "local_port": t.LocalPort},
		},
		"enabled":        true,
		"alloc":          nil,
		"firewall_id":    nil,
		"proxy_protocol": nil,
	}
	var v struct {
		ID string `json:"id"`
	}
	err := c.call(ctx, "/tunnels/create", req, &v)
	return v.ID, err
}

func (c *client) enableTunnel(ctx context.Context, id string, on bool) error {
	return c.call(ctx, "/tunnels/enable", map[string]any{"tunnel_id": id, "enabled": on}, nil)
}

func (c *client) deleteTunnel(ctx context.Context, id string) error {
	err := c.call(ctx, "/tunnels/delete", map[string]any{"tunnel_id": id}, nil)
	if IsCode(err, "TunnelNotFound") {
		return nil
	}
	return err
}

// Claiming: the panel makes up a code, the owner approves it at
// playit.gg/claim/<code>, and the approved code is exchanged for the agent's
// secret.

func (c *client) claimSetup(ctx context.Context, code string) (string, error) {
	var state string // WaitingForUserVisit, WaitingForUser, UserAccepted, UserRejected
	err := c.call(ctx, "/claim/setup", map[string]any{"code": code, "agent_type": "self-managed", "version": "Block Party (playit " + AgentVersion + ")"}, &state)
	return state, err
}

func (c *client) claimExchange(ctx context.Context, code string) (string, error) {
	var v struct {
		SecretKey string `json:"secret_key"`
	}
	err := c.call(ctx, "/claim/exchange", map[string]any{"code": code}, &v)
	return v.SecretKey, err
}
