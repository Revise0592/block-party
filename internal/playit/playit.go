// Package playit lets friends outside the house join through playit.gg, with
// no port forwarding: the panel links a playit.gg account, runs playit's
// agent next to the game servers, and keeps one playit tunnel for each
// server (and protocol) that's open to friends.
//
// A tunnel is created the first time its server is opened, disabled (not
// deleted) when the server is closed, so the address friends have keeps
// working when it's opened again, and deleted when the server is.
package playit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tunnel types playit.gg knows. Minecraft Java tunnels also get an SRV
// record, so Java players can leave out the port.
const (
	TypeJava    = "minecraft-java"
	TypeBedrock = "minecraft-bedrock"
)

// Want is a tunnel a server needs.
type Want struct {
	ServerID string
	Name     string // the server's name
	Port     int    // its port in the container
	Proto    string // "tcp" or "udp"
	Type     string // TypeJava, TypeBedrock, or "" for a plain tunnel
	Open     bool   // friends may come in now; otherwise it's kept, disabled
}

// Key names the tunnel for a server and protocol: "my-world/udp".
func Key(serverID, proto string) string { return serverID + "/" + proto }

func (w Want) key() string { return Key(w.ServerID, w.Proto) }

// TunnelState is one of the panel's tunnels.
type TunnelState struct {
	Key      string `json:"key"`
	ServerID string `json:"serverID"`
	Name     string `json:"name"`
	Proto    string `json:"proto"`
	Port     int    `json:"port"` // in the container
	// Address and PublicPort are what friends type. Empty while playit.gg
	// is still giving the tunnel an address.
	Address    string `json:"address,omitempty"`
	PublicPort int    `json:"publicPort,omitempty"`
	Enabled    bool   `json:"enabled"`
	// Ready: enabled, with an address, and the agent is running.
	Ready   bool   `json:"ready"`
	Problem string `json:"problem,omitempty"`
}

// Usage is how many of the account's ports are in use.
type Usage struct {
	Used    int `json:"used"`
	Allowed int `json:"allowed"`
}

// Status is everything the panel shows about playit.gg.
type Status struct {
	Linked        bool          `json:"linked"`
	AccountStatus string        `json:"accountStatus,omitempty"`
	AccountNote   string        `json:"accountNote,omitempty"`
	Agent         string        `json:"agent"`
	AgentError    string        `json:"agentError,omitempty"`
	AgentLog      []string      `json:"agentLog"`
	TCP           Usage         `json:"tcp"`
	UDP           Usage         `json:"udp"`
	Error         string        `json:"error,omitempty"`
	Tunnels       []TunnelState `json:"tunnels"`
	// Claim is the link being approved, while there is one.
	Claim string `json:"claim,omitempty"`
}

// Options configure a Manager.
type Options struct {
	Dir string // where it keeps its files (<data>/playit)
	// API is playit.gg's API; empty means DefaultAPI.
	API string
	// AgentPath runs this agent instead of downloading playit's.
	AgentPath string
	Log       *slog.Logger
}

// Manager links playit.gg and keeps the tunnels.
type Manager struct {
	opts  Options
	log   *slog.Logger
	http  *http.Client
	agent *agent

	syncMu sync.Mutex // one Sync (or unlink) at a time

	mu      sync.Mutex
	secret  string
	saved   saved
	status  Status
	claim   string
	claimAt time.Time
	tunnels map[string]TunnelState
}

// saved is kept in <dir>/tunnels.json. The secret is kept apart, in
// <dir>/secret, where the agent reads it.
type saved struct {
	AgentID string               `json:"agentID,omitempty"`
	Tunnels map[string]tunnelRec `json:"tunnels"`
}

type tunnelRec struct {
	ID    string `json:"id"`
	Port  int    `json:"port"`
	Type  string `json:"type,omitempty"`
	Name  string `json:"name"`
	Label string `json:"label"` // the server's name
}

// New reads what was saved.
func New(opts Options) *Manager {
	if opts.API == "" {
		opts.API = DefaultAPI
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("src", "playit")
	m := &Manager{opts: opts, log: log, http: &http.Client{}, agent: newAgent(log), tunnels: map[string]TunnelState{}}
	m.saved.Tunnels = map[string]tunnelRec{}
	if b, err := os.ReadFile(m.secretPath()); err == nil {
		m.secret = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(m.savedPath()); err == nil {
		_ = json.Unmarshal(b, &m.saved)
		if m.saved.Tunnels == nil {
			m.saved.Tunnels = map[string]tunnelRec{}
		}
	}
	return m
}

func (m *Manager) secretPath() string { return filepath.Join(m.opts.Dir, "secret") }
func (m *Manager) savedPath() string  { return filepath.Join(m.opts.Dir, "tunnels.json") }
func (m *Manager) socketPath() string { return filepath.Join(m.opts.Dir, "agent.sock") }

func (m *Manager) client(secret string) *client {
	return &client{base: m.opts.API, secret: secret, http: m.http}
}

// Linked reports whether a playit.gg account is linked.
func (m *Manager) Linked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secret != ""
}

// Status returns the latest state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	st := m.status
	st.Linked = m.secret != ""
	if m.claim != "" && time.Since(m.claimAt) < claimTTL {
		st.Claim = claimURL(m.claim)
	}
	st.Tunnels = append([]TunnelState(nil), st.Tunnels...)
	m.mu.Unlock()
	st.Agent, st.AgentError, st.AgentLog = m.agent.status()
	if st.AgentLog == nil {
		st.AgentLog = []string{}
	}
	if st.Tunnels == nil {
		st.Tunnels = []TunnelState{}
	}
	return st
}

// Tunnel returns the state of a server's tunnel for a protocol.
func (m *Manager) Tunnel(serverID, proto string) (TunnelState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[Key(serverID, proto)]
	return t, ok
}

// ---- linking ----

const claimTTL = 15 * time.Minute

func claimURL(code string) string { return "https://playit.gg/claim/" + code }

// StartClaim makes a new code for the owner to approve on playit.gg and
// returns the link to open.
func (m *Manager) StartClaim(ctx context.Context) (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)
	// Telling playit about the code before the owner opens the link.
	if _, err := m.client("").claimSetup(ctx, code); err != nil {
		return "", friendly(err)
	}
	m.mu.Lock()
	m.claim, m.claimAt = code, time.Now()
	m.mu.Unlock()
	return claimURL(code), nil
}

// Claim states.
const (
	ClaimWaiting  = "waiting"  // not approved on playit.gg yet
	ClaimLinked   = "linked"   // approved: the account is linked
	ClaimRejected = "rejected" // the owner said no on playit.gg
	ClaimNone     = "none"     // there's no link being approved
)

// CheckClaim asks playit.gg whether the link was approved, and links the
// account when it was.
func (m *Manager) CheckClaim(ctx context.Context) (string, error) {
	m.mu.Lock()
	code := m.claim
	if code != "" && time.Since(m.claimAt) > claimTTL {
		m.claim, code = "", ""
	}
	m.mu.Unlock()
	if code == "" {
		if m.Linked() {
			return ClaimLinked, nil
		}
		return ClaimNone, nil
	}
	c := m.client("")
	state, err := c.claimSetup(ctx, code)
	if err != nil {
		return "", friendly(err)
	}
	switch state {
	case "UserRejected":
		m.endClaim(code)
		return ClaimRejected, nil
	case "UserAccepted":
	default:
		return ClaimWaiting, nil
	}
	secret, err := c.claimExchange(ctx, code)
	if err != nil {
		return "", friendly(err)
	}
	if err := m.link(ctx, secret); err != nil {
		return "", err
	}
	m.endClaim(code)
	return ClaimLinked, nil
}

func (m *Manager) endClaim(code string) {
	m.mu.Lock()
	if m.claim == code {
		m.claim = ""
	}
	m.mu.Unlock()
}

// link checks the secret and keeps it.
func (m *Manager) link(ctx context.Context, secret string) error {
	secret = strings.TrimSpace(secret)
	rd, err := m.client(secret).runData(ctx)
	if err != nil {
		return friendly(err)
	}
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	if err := os.MkdirAll(m.opts.Dir, 0o700); err != nil {
		return err
	}
	if err := writeFile(m.secretPath(), []byte(secret+"\n")); err != nil {
		return err
	}
	m.mu.Lock()
	m.secret = secret
	if m.saved.AgentID != rd.AgentID {
		// Another playit agent: the old tunnels aren't its.
		m.saved = saved{AgentID: rd.AgentID, Tunnels: map[string]tunnelRec{}}
		m.tunnels = map[string]TunnelState{}
	}
	m.status = Status{AccountStatus: rd.AccountStatus, AccountNote: accountNote(rd.AccountStatus)}
	m.saveLocked()
	m.mu.Unlock()
	m.agent.clearLog()
	m.log.Info("linked a playit.gg account", "agent", rd.AgentID)
	return nil
}

// Unlink deletes the panel's tunnels, stops the agent and forgets the
// account.
func (m *Manager) Unlink(ctx context.Context) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	m.mu.Lock()
	secret := m.secret
	recs := m.saved.Tunnels
	m.mu.Unlock()
	if secret != "" {
		c := m.client(secret)
		for k, r := range recs {
			if err := c.deleteTunnel(ctx, r.ID); err != nil {
				m.log.Warn("couldn't delete a playit.gg tunnel", "tunnel", k, "error", err)
			}
		}
	}
	m.agent.halt()
	m.agent.clearLog()
	if err := os.Remove(m.secretPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.mu.Lock()
	m.secret = ""
	m.saved = saved{Tunnels: map[string]tunnelRec{}}
	m.tunnels = map[string]TunnelState{}
	m.status = Status{}
	m.saveLocked()
	m.mu.Unlock()
	m.log.Info("unlinked playit.gg")
	return nil
}

// Stop stops the agent (when the panel stops).
func (m *Manager) Stop() { m.agent.halt() }

// ---- keeping the tunnels ----

// Sync makes the tunnels match: on is whether friends may come in through
// playit.gg at all, and want lists every server's tunnels (closed ones
// too, so their tunnels are kept). It reports whether something is still
// being set up, so the caller can look again soon.
func (m *Manager) Sync(ctx context.Context, on bool, want []Want) (busy bool) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	m.mu.Lock()
	secret := m.secret
	m.mu.Unlock()
	if secret == "" {
		m.agent.halt()
		m.mu.Lock()
		m.status = Status{}
		m.tunnels = map[string]TunnelState{}
		m.mu.Unlock()
		return false
	}
	anyOpen := false
	for i := range want {
		if !on {
			want[i].Open = false
		}
		anyOpen = anyOpen || want[i].Open
	}

	st := Status{}
	// The agent runs while something is open.
	if anyOpen {
		path := m.opts.AgentPath
		var err error
		if path == "" {
			path, err = ensureAgent(ctx, filepath.Join(m.opts.Dir, "bin"))
		}
		if err != nil {
			st.Error = err.Error()
		} else {
			m.agent.run([]string{path, "--secret-path", m.secretPath(), "--socket-path", m.socketPath(), "--platform-docker"})
		}
	} else {
		m.agent.halt()
	}

	c := m.client(secret)
	rd, err := c.runData(ctx)
	if err == nil {
		st.AccountStatus, st.AccountNote = rd.AccountStatus, accountNote(rd.AccountStatus)
		m.mu.Lock()
		if m.saved.AgentID == "" {
			m.saved.AgentID = rd.AgentID
		}
		m.mu.Unlock()
	}
	var list tunnelList
	if err == nil {
		list, err = c.listTunnels(ctx)
	}
	if err != nil {
		if IsCode(err, "auth") {
			st.Error = "playit.gg doesn't accept this panel's link any more (was the agent deleted on playit.gg?). Unlink and link again."
		} else if st.Error == "" {
			st.Error = friendly(err).Error()
		}
		m.mu.Lock()
		// Keep showing the tunnels as they were.
		st.Tunnels = m.status.Tunnels
		m.status = st
		m.mu.Unlock()
		return false // tried again in a minute
	}
	st.TCP = Usage{Used: list.TCP.Claimed, Allowed: list.TCP.Allowed}
	st.UDP = Usage{Used: list.UDP.Claimed, Allowed: list.UDP.Allowed}
	byID := map[string]tunnel{}
	for _, t := range list.Tunnels {
		byID[t.ID] = t
	}

	m.mu.Lock()
	agentID := m.saved.AgentID
	recs := map[string]tunnelRec{}
	for k, r := range m.saved.Tunnels {
		recs[k] = r
	}
	m.mu.Unlock()
	changed := false
	wanted := map[string]Want{}
	for _, w := range want {
		wanted[w.key()] = w
	}

	// Tunnels that aren't wanted any more, or don't fit (the server's port
	// changed): deleted.
	for k, r := range recs {
		w, ok := wanted[k]
		if ok && r.Port == w.Port && r.Type == w.Type {
			if _, there := byID[r.ID]; there {
				continue
			}
			// Deleted on playit.gg: made again below if it's open.
			delete(recs, k)
			changed = true
			continue
		}
		if err := c.deleteTunnel(ctx, r.ID); err != nil {
			m.log.Warn("couldn't delete a playit.gg tunnel", "tunnel", k, "error", err)
			continue
		}
		m.log.Info("deleted a playit.gg tunnel", "tunnel", k)
		delete(byID, r.ID)
		delete(recs, k)
		changed = true
	}

	keys := make([]string, 0, len(wanted))
	for k := range wanted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tunnels := map[string]TunnelState{}
	for _, k := range keys {
		w := wanted[k]
		ts := TunnelState{Key: k, ServerID: w.ServerID, Name: w.Name, Proto: w.Proto, Port: w.Port}
		r, have := recs[k]
		name := tunnelName(w)
		if !have {
			// One made before the panel lost its records (or a restore).
			if t, ok := adoptable(byID, recs, name, agentID, w); ok {
				r, have = tunnelRec{ID: t.ID, Port: w.Port, Type: w.Type, Name: name, Label: w.Name}, true
				recs[k] = r
				changed = true
			}
		}
		if !have && w.Open {
			id, err := c.createTunnel(ctx, newTunnel{Name: name, TunnelType: w.Type, PortType: w.Proto, AgentID: agentID, LocalIP: "127.0.0.1", LocalPort: w.Port})
			switch {
			case IsCode(err, "AgentVersionTooOld") || IsCode(err, "AgentNotFound"):
				// A new agent can't have tunnels until it has connected.
				ts.Problem = "Waiting for playit.gg's agent to connect…"
				busy = true
			case err != nil:
				ts.Problem = friendly(err).Error()
				m.log.Warn("couldn't create a playit.gg tunnel", "tunnel", k, "error", err)
			default:
				m.log.Info("created a playit.gg tunnel", "tunnel", k)
				r, have = tunnelRec{ID: id, Port: w.Port, Type: w.Type, Name: name, Label: w.Name}, true
				recs[k] = r
				changed = true
				nt := tunnel{ID: id, Active: true}
				nt.Alloc.Status = "pending"
				byID[id] = nt
			}
		}
		if !have {
			if ts.Problem != "" || w.Open {
				tunnels[k] = ts
			}
			continue
		}
		if r.Label != w.Name {
			r.Label = w.Name
			recs[k] = r
			changed = true
		}
		t := byID[r.ID]
		if t.Active != w.Open {
			if err := c.enableTunnel(ctx, r.ID, w.Open); err != nil {
				ts.Problem = friendly(err).Error()
			} else {
				t.Active = w.Open
				m.log.Info("playit.gg tunnel "+map[bool]string{true: "enabled", false: "disabled"}[w.Open], "tunnel", k)
			}
		}
		ts.Enabled = t.Active
		switch t.Alloc.Status {
		case "allocated":
			ts.Address, ts.PublicPort = t.Alloc.Data.AssignedDomain, t.Alloc.Data.PortStart
		case "disabled":
			if ts.Problem == "" {
				ts.Problem = offlineReason(t.Alloc.Data.Reason)
			}
		default:
			if w.Open {
				busy = true
				if ts.Problem == "" {
					ts.Problem = "playit.gg is giving it an address…"
				}
			}
		}
		if t.DisabledReason != nil && ts.Problem == "" && w.Open {
			ts.Problem = offlineReason(*t.DisabledReason)
		}
		tunnels[k] = ts
	}

	agentState, _, _ := m.agent.status()
	st.Tunnels = []TunnelState{}
	for _, k := range keys {
		ts, ok := tunnels[k]
		if !ok {
			continue
		}
		ts.Ready = ts.Enabled && ts.Address != "" && ts.Problem == "" && agentState == AgentRunning
		if ts.Enabled && ts.Address != "" && agentState != AgentRunning && ts.Problem == "" {
			ts.Problem = "playit.gg's agent isn't running."
			busy = true
		}
		tunnels[k] = ts
		st.Tunnels = append(st.Tunnels, ts)
	}
	m.mu.Lock()
	if changed {
		m.saved.Tunnels = recs
		m.saveLocked()
	}
	m.tunnels = tunnels
	m.status = st
	m.mu.Unlock()
	return busy
}

// adoptable finds a tunnel this panel made for w but has no record of: its
// name, on this agent, to the same port, and not someone else's record.
func adoptable(byID map[string]tunnel, recs map[string]tunnelRec, name, agentID string, w Want) (tunnel, bool) {
	taken := map[string]bool{}
	for _, r := range recs {
		taken[r.ID] = true
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := byID[id]
		if taken[id] || t.name() != name || t.PortType != w.Proto || t.Origin == nil || t.Origin.Data.AgentID != agentID {
			continue
		}
		if p := t.Origin.Data.LocalPort; p != nil && *p != w.Port {
			continue
		}
		return t, true
	}
	return tunnel{}, false
}

var unsafeName = regexp.MustCompile(`[^a-z0-9-]+`)

// tunnelName is the tunnel's name on playit.gg: "blockparty-my-world-java".
func tunnelName(w Want) string {
	id := strings.Trim(unsafeName.ReplaceAllString(strings.ToLower(w.ServerID), "-"), "-")
	if len(id) > 40 {
		id = id[:40]
	}
	kind := w.Proto
	switch w.Type {
	case TypeJava:
		kind = "java"
	case TypeBedrock:
		kind = "bedrock"
	}
	return "blockparty-" + id + "-" + kind
}

func (m *Manager) saveLocked() {
	if err := os.MkdirAll(m.opts.Dir, 0o700); err != nil {
		m.log.Warn("couldn't save the playit.gg tunnels", "error", err)
		return
	}
	b, _ := json.MarshalIndent(m.saved, "", "  ")
	if err := writeFile(m.savedPath(), b); err != nil {
		m.log.Warn("couldn't save the playit.gg tunnels", "error", err)
	}
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// friendly turns playit's failure names into something to act on.
func friendly(err error) error {
	var ae *APIError
	if !errors.As(err, &ae) {
		return err
	}
	switch ae.Code {
	case "RequiresPlayitPremium":
		return errors.New("playit.gg's free plan has no room for another tunnel (it allows 4 TCP and 4 UDP). Delete a server you don't use, or upgrade to playit Premium")
	case "RequiresVerifiedAccount":
		return errors.New("verify your email address on playit.gg first, then check again")
	case "InvalidTunnelName":
		return errors.New("playit.gg didn't accept the tunnel's name")
	case "CodeExpired", "CodeNotFound":
		return errors.New("the playit.gg link expired; start again")
	case "TooManyRequests":
		return errors.New("playit.gg asked the panel to slow down; it tries again in a minute")
	case "auth":
		return errors.New("playit.gg didn't accept the panel's link")
	}
	return ae
}

func offlineReason(r string) string {
	switch r {
	case "requires-premium":
		return "playit.gg says this tunnel needs playit Premium."
	case "over-port-limit":
		return "playit.gg's free plan has no room for this tunnel (4 TCP and 4 UDP)."
	case "public-port-not-available":
		return "playit.gg's port for this tunnel isn't available."
	case "":
		return "playit.gg isn't serving this tunnel."
	}
	return "playit.gg isn't serving this tunnel (" + r + ")."
}

func accountNote(s string) string {
	switch s {
	case "", "ready":
		return ""
	case "guest":
		return "This is a guest account on playit.gg. Sign up there to keep it."
	case "email-not-verified":
		return "Verify your email address on playit.gg; until then it may not make tunnels."
	case "agent-over-limit":
		return "Your playit.gg account has more agents than its plan allows. Delete an old one on playit.gg."
	case "agent-disabled":
		return "This agent is turned off on playit.gg. Turn it on there."
	case "banned", "account-delete-scheduled":
		return "playit.gg has closed this account (" + s + ")."
	}
	return "playit.gg says: " + s + "."
}
