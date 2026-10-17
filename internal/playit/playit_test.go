package playit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is enough of playit.gg's API for the panel.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	accepted  bool
	tooOld    int // answer AgentVersionTooOld to this many creates first
	tunnels   map[string]map[string]any
	nextID    int
	created   []map[string]any
	enabled   []string
	deleted   []string
	allocated bool // new tunnels get an address straight away
}

const testSecret = "s3cr3t-agent-key"

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, tunnels: map[string]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func reply(w http.ResponseWriter, status string, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "data": data})
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.HasPrefix(r.URL.Path, "/claim/") {
		switch r.URL.Path {
		case "/claim/setup":
			if req["agent_type"] != "self-managed" || req["code"] == "" {
				f.t.Errorf("claim setup: %v", req)
			}
			reply(w, "success", map[bool]string{false: "WaitingForUserVisit", true: "UserAccepted"}[f.accepted])
		case "/claim/exchange":
			reply(w, "success", map[string]string{"secret_key": testSecret})
		}
		return
	}
	if r.Header.Get("Authorization") != "Agent-Key "+testSecret {
		reply(w, "error", map[string]any{"type": "auth", "message": "InvalidAgentKey"})
		return
	}
	switch r.URL.Path {
	case "/agents/rundata":
		reply(w, "success", map[string]any{"agent_id": "agent-1", "account_status": "ready"})
	case "/tunnels/list":
		list := []any{}
		for _, t := range f.tunnels {
			list = append(list, t)
		}
		reply(w, "success", map[string]any{"tunnels": list,
			"tcp_alloc": map[string]int{"allowed": 4, "claimed": f.count("tcp")},
			"udp_alloc": map[string]int{"allowed": 4, "claimed": f.count("udp")}})
	case "/tunnels/create":
		if f.tooOld > 0 {
			f.tooOld--
			reply(w, "fail", "AgentVersionTooOld")
			return
		}
		f.nextID++
		id := "tun-" + string(rune('0'+f.nextID))
		f.created = append(f.created, req)
		origin := req["origin"].(map[string]any)["data"].(map[string]any)
		t := map[string]any{"id": id, "name": req["name"], "tunnel_type": req["tunnel_type"], "port_type": req["port_type"],
			"active": true, "alloc": map[string]any{"status": "pending"}, "disabled_reason": nil,
			"origin": map[string]any{"type": "agent", "data": map[string]any{"agent_id": origin["agent_id"], "local_ip": origin["local_ip"], "local_port": origin["local_port"]}}}
		if f.allocated {
			f.allocate(t)
		}
		f.tunnels[id] = t
		reply(w, "success", map[string]string{"id": id})
	case "/tunnels/enable":
		id, _ := req["tunnel_id"].(string)
		t, ok := f.tunnels[id]
		if !ok {
			reply(w, "fail", "TunnelNotFound")
			return
		}
		t["active"] = req["enabled"]
		f.enabled = append(f.enabled, id+"="+map[bool]string{true: "on", false: "off"}[req["enabled"] == true])
		reply(w, "success", nil)
	case "/tunnels/delete":
		id, _ := req["tunnel_id"].(string)
		if _, ok := f.tunnels[id]; !ok {
			reply(w, "fail", "TunnelNotFound")
			return
		}
		delete(f.tunnels, id)
		f.deleted = append(f.deleted, id)
		reply(w, "success", nil)
	default:
		w.WriteHeader(http.StatusNotFound)
		reply(w, "error", map[string]any{"type": "path-not-found"})
	}
}

func (f *fakeAPI) count(proto string) int {
	n := 0
	for _, t := range f.tunnels {
		if t["port_type"] == proto {
			n++
		}
	}
	return n
}

func (f *fakeAPI) allocate(t map[string]any) {
	domain := strings.TrimPrefix(t["name"].(string), "blockparty-") + ".joinmc.link"
	port := 20000 + len(f.created)
	t["alloc"] = map[string]any{"status": "allocated", "data": map[string]any{"assigned_domain": domain, "port_start": port}}
}

func (f *fakeAPI) allocateAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tunnels {
		f.allocate(t)
	}
}

// fakeAgent is a stand-in for playit's agent that notes its arguments.
func fakeAgent(t *testing.T) (path, argsFile string) {
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	path = filepath.Join(dir, "agent")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\necho '\x1b[32m INFO\x1b[0m agent started'\nexec sleep 60\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPlayitLinkAndTunnels(t *testing.T) {
	ctx := context.Background()
	f := newFakeAPI(t)
	agentPath, argsFile := fakeAgent(t)
	dir := t.TempDir()
	m := New(Options{Dir: dir, API: f.srv.URL, AgentPath: agentPath})
	t.Cleanup(m.Stop)

	java := []Want{
		{ServerID: "the-gaff", Name: "The Gaff", Port: 19134, Proto: "tcp", Type: TypeJava, Open: true},
		{ServerID: "the-gaff", Name: "The Gaff", Port: 19134, Proto: "udp", Type: TypeBedrock, Open: true},
	}
	bedrock := Want{ServerID: "kids", Name: "Kids", Port: 19136, Proto: "udp", Type: TypeBedrock}

	// Not linked: nothing happens.
	m.Sync(ctx, true, append(java, bedrock))
	if m.Linked() || len(f.created) != 0 {
		t.Fatal("did something without a link")
	}

	// Linking.
	url, err := m.StartClaim(ctx)
	if err != nil || !strings.HasPrefix(url, "https://playit.gg/claim/") {
		t.Fatalf("claim: %q %v", url, err)
	}
	if st, _ := m.CheckClaim(ctx); st != ClaimWaiting {
		t.Fatalf("claim state %q before approval", st)
	}
	f.mu.Lock()
	f.accepted = true
	f.mu.Unlock()
	if st, err := m.CheckClaim(ctx); st != ClaimLinked || err != nil {
		t.Fatalf("claim state %q, %v after approval", st, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "secret")); strings.TrimSpace(string(b)) != testSecret {
		t.Fatalf("secret file has %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "secret")); fi.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode %v", fi.Mode().Perm())
	}
	if m.Status().Claim != "" {
		t.Error("claim link still shown after linking")
	}

	// Opening: the agent starts; tunnels wait for it to connect, then are
	// made and wait for an address.
	f.mu.Lock()
	f.tooOld = 1
	f.mu.Unlock()
	if !m.Sync(ctx, true, append(append([]Want{}, java...), bedrock)) {
		t.Fatal("not busy while the agent connects")
	}
	waitFor(t, "the agent", func() bool { s, _, _ := m.agent.status(); return s == AgentRunning })
	if !m.Sync(ctx, true, append(append([]Want{}, java...), bedrock)) {
		t.Fatal("not busy while tunnels get addresses")
	}
	if len(f.created) != 2 {
		t.Fatalf("created %d tunnels, want 2 (the closed server gets none)", len(f.created))
	}
	for _, c := range f.created {
		o := c["origin"].(map[string]any)["data"].(map[string]any)
		if o["agent_id"] != "agent-1" || o["local_ip"] != "127.0.0.1" || o["local_port"] != float64(19134) {
			t.Errorf("tunnel origin %v", o)
		}
	}
	if f.created[0]["tunnel_type"] == f.created[1]["tunnel_type"] {
		t.Errorf("tunnel types %v and %v", f.created[0]["tunnel_type"], f.created[1]["tunnel_type"])
	}
	if ts, ok := m.Tunnel("the-gaff", "tcp"); !ok || ts.Ready || ts.Problem == "" {
		t.Errorf("tunnel without an address: %+v", ts)
	}
	f.allocateAll()
	if m.Sync(ctx, true, append(append([]Want{}, java...), bedrock)) {
		t.Fatal("still busy once everything has an address")
	}
	ts, _ := m.Tunnel("the-gaff", "tcp")
	if !ts.Ready || ts.Address != "the-gaff-java.joinmc.link" || ts.PublicPort == 0 {
		t.Fatalf("java tunnel %+v", ts)
	}
	if ts, _ := m.Tunnel("the-gaff", "udp"); !ts.Ready || ts.Address != "the-gaff-bedrock.joinmc.link" {
		t.Fatalf("console tunnel %+v", ts)
	}
	st := m.Status()
	if st.TCP != (Usage{Used: 1, Allowed: 4}) || st.UDP != (Usage{Used: 1, Allowed: 4}) || st.AccountStatus != "ready" {
		t.Errorf("status %+v", st)
	}
	if len(st.AgentLog) == 0 || strings.Contains(st.AgentLog[0], "\x1b") {
		t.Errorf("agent log %q", st.AgentLog)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--secret-path "+filepath.Join(dir, "secret")) || strings.Contains(string(args), testSecret) {
		t.Errorf("agent args %q", args)
	}

	// Closing keeps the tunnels (and their addresses), disabled, and stops
	// the agent.
	closed := []Want{java[0], java[1]}
	closed[0].Open, closed[1].Open = false, false
	m.Sync(ctx, true, append(closed, bedrock))
	if len(f.deleted) != 0 || len(f.enabled) != 2 || !strings.HasSuffix(f.enabled[0], "=off") {
		t.Fatalf("closing: deleted %v, enabled %v", f.deleted, f.enabled)
	}
	if s, _, _ := m.agent.status(); s != AgentStopped {
		t.Errorf("agent %s with nothing open", s)
	}
	// Outside access off works the same way.
	m.Sync(ctx, false, append(append([]Want{}, java...), bedrock))
	if len(f.enabled) != 2 {
		t.Errorf("enabled %v while outside access is off", f.enabled)
	}
	// Opened again: the same tunnels.
	m.Sync(ctx, true, append(append([]Want{}, java...), bedrock))
	if len(f.created) != 2 || len(f.enabled) != 4 {
		t.Fatalf("reopening: created %d, enabled %v", len(f.created), f.enabled)
	}
	if ts2, _ := m.Tunnel("the-gaff", "tcp"); ts2.Address != ts.Address {
		t.Errorf("address changed from %s to %s", ts.Address, ts2.Address)
	}

	// Console players turned off: the UDP tunnel goes. A port change makes
	// a new one.
	moved := java[0]
	moved.Port = 19140
	m.Sync(ctx, true, []Want{moved, bedrock})
	if len(f.deleted) != 2 || len(f.created) != 3 {
		t.Fatalf("after changes: deleted %v, created %d", f.deleted, len(f.created))
	}

	// A new panel (after a restart) picks up where this one left off.
	m2 := New(Options{Dir: dir, API: f.srv.URL, AgentPath: agentPath})
	t.Cleanup(m2.Stop)
	f.allocateAll()
	m2.Sync(ctx, true, []Want{moved, bedrock})
	if len(f.created) != 3 {
		t.Fatalf("restart made %d tunnels", len(f.created)-3)
	}
	if ts, ok := m2.Tunnel("the-gaff", "tcp"); !ok || ts.Address == "" {
		t.Errorf("after restart: %+v", ts)
	}
	m2.Stop()

	// Unlinking deletes the panel's tunnels and forgets the account.
	if err := m.Unlink(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.tunnels) != 0 || m.Linked() {
		t.Errorf("after unlinking: %d tunnels left, linked %v", len(f.tunnels), m.Linked())
	}
	if _, err := os.Stat(filepath.Join(dir, "secret")); !os.IsNotExist(err) {
		t.Error("secret file kept")
	}
}

func TestPlayitAdoptsItsOwnTunnels(t *testing.T) {
	ctx := context.Background()
	f := newFakeAPI(t)
	f.allocated = true
	agentPath, _ := fakeAgent(t)
	dir := t.TempDir()
	m := New(Options{Dir: dir, API: f.srv.URL, AgentPath: agentPath})
	t.Cleanup(m.Stop)
	if err := m.link(ctx, testSecret); err != nil {
		t.Fatal(err)
	}
	w := []Want{{ServerID: "kids", Name: "Kids", Port: 19136, Proto: "udp", Type: TypeBedrock, Open: true}}
	m.Sync(ctx, true, w)
	// The panel's records are lost (a restore of an old backup, say), and
	// someone has a tunnel of their own on the account.
	os.Remove(filepath.Join(dir, "tunnels.json"))
	f.mu.Lock()
	f.tunnels["mine"] = map[string]any{"id": "mine", "name": "blockparty-kids-bedrock", "port_type": "udp", "active": true,
		"alloc": map[string]any{"status": "pending"}, "origin": map[string]any{"type": "agent", "data": map[string]any{"agent_id": "someone-else"}}}
	f.mu.Unlock()
	m2 := New(Options{Dir: dir, API: f.srv.URL, AgentPath: agentPath})
	t.Cleanup(m2.Stop)
	m2.Sync(ctx, true, w)
	if len(f.created) != 1 {
		t.Errorf("made %d tunnels; the old one should have been taken back", len(f.created))
	}
	if _, ok := f.tunnels["mine"]; !ok {
		t.Error("someone else's tunnel was touched")
	}
}

func TestPlayitErrors(t *testing.T) {
	ctx := context.Background()
	f := newFakeAPI(t)
	m := New(Options{Dir: t.TempDir(), API: f.srv.URL})
	if err := m.link(ctx, "wrong"); err == nil {
		t.Fatal("a wrong secret was accepted")
	}
	c := m.client(testSecret)
	_, err := c.createTunnel(ctx, newTunnel{Name: "x", PortType: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.tooOld = 1
	f.mu.Unlock()
	_, err = c.createTunnel(ctx, newTunnel{Name: "x", PortType: "tcp"})
	if !IsCode(err, "AgentVersionTooOld") {
		t.Errorf("got %v", err)
	}
	if err := friendly(&APIError{Code: "RequiresPlayitPremium"}); !strings.Contains(err.Error(), "free plan") {
		t.Errorf("friendly: %v", err)
	}
	if got := tunnelName(Want{ServerID: "My World!", Proto: "udp"}); got != "blockparty-my-world-udp" {
		t.Errorf("name %q", got)
	}
}

func TestEnsureAgentChecksTheDownload(t *testing.T) {
	b, ok := agentBuilds[runtime.GOARCH]
	if runtime.GOOS != "linux" || !ok {
		t.Skip("no agent for this platform")
	}
	body := []byte("not the agent")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	old := agentURL
	agentURL = func(asset string) string { return srv.URL + "/" + asset }
	defer func() { agentURL = old }()
	dir := t.TempDir()
	if _, err := ensureAgent(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "isn't the expected file") {
		t.Fatalf("a wrong file was accepted: %v", err)
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Errorf("left %d files behind", len(files))
	}
	// The right file is kept and not downloaded again.
	sum := sha256.Sum256(body)
	agentBuilds[runtime.GOARCH] = struct{ asset, sha256 string }{b.asset, hex.EncodeToString(sum[:])}
	defer func() { agentBuilds[runtime.GOARCH] = b }()
	path, err := ensureAgent(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("agent file %v %v", fi, err)
	}
	srv.Close()
	if _, err := ensureAgent(context.Background(), dir); err != nil {
		t.Errorf("downloaded again: %v", err)
	}
}

func TestPlayitOnlyIsKept(t *testing.T) {
	dir := t.TempDir()
	m := New(Options{Dir: dir})
	if err := m.SetOnly("the-gaff", "java"); err == nil {
		t.Error("accepted a protocol that isn't tcp or udp")
	}
	if err := m.SetOnly("the-gaff", "tcp"); err != nil {
		t.Fatal(err)
	}
	if New(Options{Dir: dir}).Only("the-gaff") != "tcp" {
		t.Error("choice not kept across a restart")
	}
	m.SetOnly("the-gaff", "")
	if New(Options{Dir: dir}).Only("the-gaff") != "" {
		t.Error("choice not cleared")
	}
}
