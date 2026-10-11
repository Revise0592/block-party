package servers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeHytaleJava stands in for "java -jar HytaleServer.jar": it prints what
// Hytale prints and answers the commands the panel sends.
const fakeHytaleJava = `#!/bin/sh
echo "[2026/10/11 12:00:00   INFO]                   [HytaleServer] args: $* session=$HYTALE_SERVER_SESSION_TOKEN identity=$HYTALE_SERVER_IDENTITY_TOKEN updates=$HYTALE_DISABLE_UPDATES"
echo "[2026/10/11 12:00:01   INFO]                   [HytaleServer] Hytale Server Booted! [Multiplayer, Fresh Universe] took 1.2s"
while read line; do
  case "$line" in
    stop) echo "[2026/10/11 12:00:09   INFO]                   [HytaleServer] Shutting down"; exit 0;;
    "join "*) set -- $line; echo "[2026/10/11 12:00:02   INFO]               [HandshakeHandler] Mutual authentication complete for $2 ($3) from x (/192.168.1.20:50000, streamId=1)";;
    "leave "*) set -- $line; echo "[2026/10/11 12:00:03   INFO]                 [Universe|P] Removing player '$2' ($3)";;
    "chat "*) set -- $line; echo "[2026/10/11 12:00:04   INFO]                     [Hytale] $2: [HandshakeHandler] Mutual authentication complete for Fake ($3)";;
    *) echo "[2026/10/11 12:00:08   INFO]                   [HytaleServer] got: $line";;
  esac
done
`

type fakeHytale struct {
	mu        sync.Mutex
	srv       *httptest.Server
	version   string
	polls     map[string]int // device code -> token polls
	refreshes int
	sessions  int
	tokenN    int
	jre       []byte
	pkg       []byte
	revoked   bool // refresh tokens no longer work
	down      bool // the sessions service is down
}

func zipOf(files map[string]string) []byte {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := z.Create(name)
		w.Write([]byte(body))
	}
	z.Close()
	return buf.Bytes()
}

func newFakeHytale(t *testing.T) *fakeHytale {
	f := &fakeHytale{version: "2026.10.01-aaaa111", polls: map[string]int{}}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "jdk-25-jre/bin/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "jdk-25-jre/bin/java", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(fakeHytaleJava))})
	tw.Write([]byte(fakeHytaleJava))
	tw.Close()
	gz.Close()
	f.jre = buf.Bytes()
	f.setVersion(f.version)
	auth := func(r *http.Request, prefix string) bool {
		return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "+prefix)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		enc := json.NewEncoder(w)
		r.ParseForm()
		switch p := r.URL.Path; {
		case p == "/oauth2/device/auth" && r.Method == http.MethodPost:
			client := r.PostForm.Get("client_id")
			if (client == "hytale-downloader" && r.PostForm.Get("scope") != "offline auth:downloader") ||
				(client == "hytale-server" && r.PostForm.Get("scope") != "openid offline auth:server") {
				w.WriteHeader(400)
				return
			}
			enc.Encode(map[string]any{"device_code": "dev-" + client, "user_code": strings.ToUpper(client[7:11]) + "-1234",
				"verification_uri": "https://accounts.hytale.com/device", "verification_uri_complete": "https://oauth.accounts.hytale.com/oauth2/device/verify?user_code=X",
				"expires_in": 900, "interval": 1})
		case p == "/oauth2/token":
			client := r.PostForm.Get("client_id")
			kind := "dl"
			if client == "hytale-server" {
				kind = "srv"
			}
			switch r.PostForm.Get("grant_type") {
			case "urn:ietf:params:oauth:grant-type:device_code":
				code := r.PostForm.Get("device_code")
				f.polls[code]++
				if f.polls[code] < 2 {
					w.WriteHeader(400)
					enc.Encode(map[string]string{"error": "authorization_pending"})
					return
				}
			case "refresh_token":
				if f.revoked || !strings.HasPrefix(r.PostForm.Get("refresh_token"), "refresh-"+kind) {
					w.WriteHeader(400)
					enc.Encode(map[string]string{"error": "invalid_grant"})
					return
				}
				f.refreshes++
			default:
				w.WriteHeader(400)
				return
			}
			f.tokenN++
			enc.Encode(map[string]any{"access_token": fmt.Sprintf("access-%s-%d", kind, f.tokenN),
				"refresh_token": fmt.Sprintf("refresh-%s-%d", kind, f.tokenN), "expires_in": 3600})
		case p == "/my-account/get-profiles":
			if !auth(r, "access-srv") {
				w.WriteHeader(401)
				return
			}
			enc.Encode(map[string]any{"owner": "acct-1", "profiles": []map[string]string{{"uuid": "11111111-2222-3333-4444-555555555555", "username": "DadBuilds"}}})
		case p == "/game-session/new":
			if f.down {
				w.WriteHeader(503)
				return
			}
			if !auth(r, "access-srv") {
				w.WriteHeader(401)
				return
			}
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["uuid"] != "11111111-2222-3333-4444-555555555555" {
				w.WriteHeader(400)
				return
			}
			f.sessions++
			enc.Encode(map[string]any{"sessionToken": fmt.Sprintf("sess-%d", f.sessions), "identityToken": "ident", "expiresAt": time.Now().Add(time.Hour)})
		case p == "/game-assets/version/release.json":
			if !auth(r, "access-dl") {
				w.Write([]byte("invalid token"))
				return
			}
			enc.Encode(map[string]string{"url": f.srv.URL + "/signed/release.json"})
		case p == "/signed/release.json":
			enc.Encode(map[string]string{"version": f.version, "download_url": "builds/" + f.version + ".zip", "sha256": sha(f.pkg)})
		case strings.HasPrefix(p, "/game-assets/builds/"):
			if !auth(r, "access-dl") {
				w.WriteHeader(401)
				return
			}
			enc.Encode(map[string]string{"url": f.srv.URL + "/files/package.zip"})
		case p == "/files/package.zip":
			w.Write(f.pkg)
		case strings.HasPrefix(p, "/adoptium/assets/latest/25/hotspot"):
			enc.Encode([]map[string]any{{"release_name": "jdk-25-test", "binary": map[string]any{"package": map[string]any{"link": f.srv.URL + "/jre25.tar.gz", "checksum": sha(f.jre)}}}})
		case p == "/jre25.tar.gz":
			w.Write(f.jre)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// setVersion puts out a new Hytale release. f.mu is held or not needed.
func (f *fakeHytale) setVersion(v string) {
	f.version = v
	f.pkg = zipOf(map[string]string{
		"Server/HytaleServer.jar":  "hytale server " + v,
		"Server/HytaleServer.aot":  "aot " + v,
		"Assets.zip":               "assets " + v,
		"Client/HytaleClient":      "the game itself",
		"../../escape.txt":         "no",
		"Server/Licenses/note.txt": "x",
	})
}

func newHytaleManager(t *testing.T, f *fakeHytale) *Manager {
	t.Helper()
	old := hytalePollEvery
	hytalePollEvery = 10 * time.Millisecond
	oldWait := hytaleSaveWait
	hytaleSaveWait = 10 * time.Millisecond
	t.Cleanup(func() { hytalePollEvery, hytaleSaveWait = old, oldWait })
	m := New(Options{DataDir: t.TempDir(), StopTimeout: 2 * time.Second, AdoptiumAPI: f.srv.URL + "/adoptium",
		HytaleOAuth: f.srv.URL, HytaleAccounts: f.srv.URL, HytaleSessions: f.srv.URL,
		PaperAPI: "http://127.0.0.1:1/none", GeyserAPI: "http://127.0.0.1:1/none", ModrinthAPI: "http://127.0.0.1:1/none", HangarAPI: "http://127.0.0.1:1/none"})
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.StopAll)
	return m
}

func signInHytale(t *testing.T, m *Manager) {
	t.Helper()
	v, err := m.StartHytaleSignIn()
	if err != nil {
		t.Fatal(err)
	}
	if v.Pending == nil || v.Pending.Step != 1 || v.Pending.Code != "DOWN-1234" || !strings.HasPrefix(v.Pending.URL, "https://") {
		t.Fatalf("first step: %+v", v)
	}
	deadline := time.Now().Add(10 * time.Second)
	sawSecond := false
	for time.Now().Before(deadline) {
		v = m.HytaleAccount()
		if v.Pending != nil && v.Pending.Step == 2 && v.Pending.Code == "SERV-1234" {
			sawSecond = true
		}
		if v.SignedIn {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !v.SignedIn || v.Username != "DadBuilds" || v.Pending != nil || v.Error != "" {
		t.Fatalf("signed in: %+v", v)
	}
	_ = sawSecond // the second step may pass between looks
}

func TestHytaleSignIn(t *testing.T) {
	f := newFakeHytale(t)
	m := newHytaleManager(t, f)
	if _, err := m.CreateHytale("Too Soon", 0); !errors.Is(err, ErrHytaleSignIn) {
		t.Errorf("created without a sign-in: %v", err)
	}
	signInHytale(t, m)
	b, err := os.ReadFile(m.hytaleAccountPath())
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(m.hytaleAccountPath()); st.Mode().Perm() != 0o600 {
		t.Errorf("account file mode %v", st.Mode())
	}
	if !strings.Contains(string(b), "refresh-dl") || !strings.Contains(string(b), "refresh-srv") {
		t.Errorf("saved: %s", b)
	}
	// Loaded again by a new panel.
	m2 := New(Options{DataDir: m.opts.DataDir, HytaleOAuth: f.srv.URL, HytaleAccounts: f.srv.URL, HytaleSessions: f.srv.URL})
	if !m2.HytaleSignedIn() {
		t.Error("not signed in after a restart")
	}
	// An expired access token is refreshed, and the new refresh token kept.
	m.hytale.mu.Lock()
	m.hytale.account.Server.Expires = time.Now().Add(-time.Minute)
	m.hytale.mu.Unlock()
	sess, err := m.newHytaleSession(t.Context())
	if err != nil || sess.Session == "" || sess.Owner != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("session: %+v %v", sess, err)
	}
	if f.refreshes != 1 {
		t.Errorf("refreshes %d", f.refreshes)
	}
	// The weekly keep-alive.
	m.hytale.mu.Lock()
	m.hytale.account.Downloader.Refreshed = time.Now().Add(-8 * 24 * time.Hour)
	m.hytale.account.Server.Refreshed = time.Now().Add(-8 * 24 * time.Hour)
	m.hytale.mu.Unlock()
	m.hytaleKeepAlive()
	if f.refreshes != 3 {
		t.Errorf("keep-alive refreshes %d", f.refreshes)
	}
	// A sign-in that ran out: signed out, with a reason.
	f.mu.Lock()
	f.revoked = true
	f.mu.Unlock()
	m.hytale.mu.Lock()
	m.hytale.account.Server.Expires = time.Now().Add(-time.Minute)
	m.hytale.mu.Unlock()
	if _, err := m.newHytaleSession(t.Context()); !errors.Is(err, ErrHytaleSignIn) {
		t.Errorf("revoked: %v", err)
	}
	if v := m.HytaleAccount(); v.SignedIn || !strings.Contains(v.Error, "Sign in again") {
		t.Errorf("after revoking: %+v", v)
	}
	// Signing out removes the file.
	signInHytaleAgain := func() {
		f.mu.Lock()
		f.revoked, f.polls = false, map[string]int{}
		f.mu.Unlock()
		signInHytale(t, m)
	}
	signInHytaleAgain()
	if err := m.SignOutHytale(); err != nil || fileExists(m.hytaleAccountPath()) || m.HytaleSignedIn() {
		t.Errorf("sign out: %v", err)
	}
}

func TestHytaleServer(t *testing.T) {
	f := newFakeHytale(t)
	m := newHytaleManager(t, f)
	signInHytale(t, m)
	st, err := m.CreateHytale("Orbis", 0)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := m.Get(st.ID)
	waitFor(t, s, "running", state(StateRunning))
	st = s.Status()
	if st.Type != TypeHytale || st.Version != "2026.10.01-aaaa111" || st.MemoryMB != 4096 {
		t.Errorf("status: %+v", st)
	}
	for file, want := range map[string]string{hytaleJar: "hytale server 2026.10.01-aaaa111", hytaleAssets: "assets 2026.10.01-aaaa111", hytaleAOT: "aot 2026.10.01-aaaa111"} {
		if got := readFile(t, filepath.Join(s.dir(), file)); got != want {
			t.Errorf("%s: %q", file, got)
		}
	}
	for _, gone := range []string{"Client", "HytaleClient", "escape.txt", "Licenses"} {
		if fileExists(filepath.Join(s.dir(), gone)) || fileExists(filepath.Join(filepath.Dir(s.dir()), gone)) {
			t.Errorf("%s was unpacked", gone)
		}
	}
	waitConsole(t, s, fmt.Sprintf("--bind 0.0.0.0:%d", st.Port))
	for _, want := range []string{"-XX:AOTCache=HytaleServer.aot", "-jar HytaleServer.jar --assets Assets.zip", "--owner-uuid 11111111-2222-3333-4444-555555555555", "session=sess-1 identity=ident updates=1", "-Xmx4096M"} {
		if !consoleHas(s, want) {
			t.Errorf("start lacks %q", want)
		}
	}
	// The owner: allowlist on, on it, and an operator, as it first started.
	waitConsole(t, s, "got: /whitelist enable")
	waitConsole(t, s, "got: /whitelist add DadBuilds")
	waitConsole(t, s, "got: /op add DadBuilds")

	// Players come and go; chat can't pretend to be a join.
	s.Command("join Kid_One 0a0a0a0a-0000-0000-0000-000000000001")
	waitConsole(t, s, "Mutual authentication complete for Kid_One")
	s.Command("chat Bob 0a0a0a0a-0000-0000-0000-000000000009")
	waitConsole(t, s, "Bob: [HandshakeHandler]")
	time.Sleep(100 * time.Millisecond)
	if p := s.Status().Players; len(p) != 1 || p[0].Name != "Kid_One" {
		t.Errorf("players: %+v", p)
	}
	// Running: by command.
	if err := s.AllowlistAdd("Kid_One", ""); err != nil {
		t.Fatal(err)
	}
	waitConsole(t, s, "got: /whitelist add Kid_One")
	if err := s.AllowlistAdd("bad name!", ""); err == nil {
		t.Error("bad name accepted")
	}
	if err := s.Kick("Kid_One", ""); err == nil {
		t.Error("kick isn't there for Hytale yet")
	}
	// Settings can't change while it runs (Hytale writes them back).
	if _, err := s.SaveSettings(map[string]string{"MaxPlayers": "10"}); !errors.Is(err, errHytaleRunning) {
		t.Errorf("settings while running: %v", err)
	}
	// A backup while it runs: a save first, then the universe is copied.
	os.MkdirAll(filepath.Join(s.dir(), "universe", "worlds", "default"), 0o755)
	os.WriteFile(filepath.Join(s.dir(), "universe", "worlds", "default", "config.json"), []byte(`{"Seed":1}`), 0o644)
	os.WriteFile(filepath.Join(s.dir(), "config.json"), []byte(`{"ServerName":"Hytale Server","MaxPlayers":100,"Defaults":{"World":"default","GameMode":"Adventure"},"Other":{"Keep":true}}`), 0o644)
	if err := s.StartBackup(); err != nil {
		t.Fatal(err)
	}
	waitConsole(t, s, "Backup saved")
	if !consoleHas(s, "got: /world save --all") {
		t.Error("no save before the backup")
	}
	b := s.Backups().Backups[0]
	c := tarContents(t, filepath.Join(m.backupsDir(s.ID()), b.Name))
	if c["universe/worlds/default/config.json"] != `{"Seed":1}` || c["config.json"] == "" || c[hytaleAssets] != "" || c[hytaleJar] != "" {
		t.Errorf("backup has %v", keys(c))
	}
	s.Command("leave Kid_One 0a0a0a0a-0000-0000-0000-000000000001")
	waitConsole(t, s, "Removing player 'Kid_One'")
	waitFor(t, s, "nobody playing", func(st Status) bool { return len(st.Players) == 0 })

	// Stopped: the files, for players it has seen; later, for others.
	s.Stop()
	waitFor(t, s, "stopped", state(StateStopped))
	os.WriteFile(s.whitelistFile(), []byte(`{"enabled":true,"list":["11111111-2222-3333-4444-555555555555"]}`), 0o644)
	os.WriteFile(s.permissionsFile(), []byte(`{"users":{"11111111-2222-3333-4444-555555555555":{"groups":["Adventure","OP"]}},"groups":{"Default":[],"OP":["*"],"Adventure":[]}}`), 0o644)
	if err := s.AllowlistAdd("Kid_One", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpAdd("Kid_One"); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.OpAdd("Stranger"); err != nil || !pending {
		t.Errorf("stranger: %v %v", pending, err)
	}
	if !strings.Contains(readFile(t, s.whitelistFile()), "0a0a0a0a-0000-0000-0000-000000000001") {
		t.Errorf("whitelist: %s", readFile(t, s.whitelistFile()))
	}
	perms := readFile(t, s.permissionsFile())
	if !strings.Contains(perms, `"Adventure": []`) || strings.Count(perms, `"OP"`) != 3 {
		t.Errorf("permissions: %s", perms)
	}
	v, err := s.Players()
	if err != nil || !v.Hytale || !v.AllowlistEnabled {
		t.Fatalf("players: %+v %v", v, err)
	}
	names := map[string]bool{}
	for _, a := range v.Allowlist {
		names[a.Name] = true
	}
	if !names["DadBuilds"] || !names["Kid_One"] {
		t.Errorf("allowlist: %+v", v.Allowlist)
	}
	if !hasPending(v.Operators, "Stranger") {
		t.Errorf("operators: %+v", v.Operators)
	}
	// Someone the panel only knows by account ID can still be taken off.
	os.WriteFile(s.whitelistFile(), []byte(`{"enabled":true,"list":["11111111-2222-3333-4444-555555555555","0a0a0a0a-0000-0000-0000-000000000001","99999999-0000-0000-0000-000000000000"]}`), 0o644)
	if err := s.AllowlistRemove("99999999-0000-0000-0000-000000000000"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, s.whitelistFile()), "99999999") {
		t.Error("not removed by account ID")
	}

	// Friends outside need the allowlist; it can't go off while open.
	if err := s.SetAllowlistEnabled(false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.whitelistFile()), `"enabled": false`) {
		t.Error("allowlist still on")
	}
	if err := s.SetOutside(true); err == nil {
		t.Error("opened with the allowlist off")
	}
	s.SetAllowlistEnabled(true)
	if err := s.SetOutside(true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAllowlistEnabled(false); !errors.Is(err, ErrOutsideOpen) {
		t.Errorf("allowlist off while open: %v", err)
	}
	s.SetOutside(false)

	// Settings, while stopped: config.json keeps what the panel doesn't know.
	sv, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{}
	for _, g := range sv.Groups {
		for _, fl := range g.Fields {
			vals[fl.Key] = fl.Value
		}
	}
	if vals["ServerName"] != "Hytale Server" || vals["Defaults.GameMode"] != "Adventure" || vals["port"] != fmt.Sprint(st.Port) || vals["MaxViewRadius"] != "32" {
		t.Errorf("settings: %v", vals)
	}
	ch, err := s.SaveSettings(map[string]string{"ServerName": "Orbis Family ", "MaxPlayers": "10", "Defaults.GameMode": "Creative"})
	if err != nil || len(ch) != 3 {
		t.Fatalf("save: %v %v", ch, err)
	}
	var cfg map[string]any
	json.Unmarshal([]byte(readFile(t, filepath.Join(s.dir(), "config.json"))), &cfg)
	if cfg["ServerName"] != "Orbis Family" || cfg["MaxPlayers"] != float64(10) || cfg["Defaults"].(map[string]any)["GameMode"] != "Creative" ||
		cfg["Defaults"].(map[string]any)["World"] != "default" || cfg["Other"] == nil {
		t.Errorf("config.json: %v", cfg)
	}
	if _, err := s.SaveSettings(map[string]string{"MaxPlayers": "0"}); err == nil {
		t.Error("0 players accepted")
	}
	if err := s.SaveRawProperties("{not json"); err == nil {
		t.Error("broken JSON saved")
	}
	if raw, err := s.RawProperties(); err != nil || !strings.Contains(raw, "Orbis Family") {
		t.Errorf("raw: %q %v", raw, err)
	}

	// The next start: a fresh session, and what was waiting.
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, "running", state(StateRunning))
	waitConsole(t, s, "session=sess-2")
	s.Command("join Stranger 0a0a0a0a-0000-0000-0000-000000000002")
	waitConsole(t, s, "got: /op add Stranger")

	// A new release: offered, and Update backs the worlds up and installs it.
	f.mu.Lock()
	f.setVersion("2026.10.08-bbbb222")
	f.mu.Unlock()
	m.hytaleLatest.mu.Lock()
	m.hytaleLatest.at = time.Time{}
	m.hytaleLatest.mu.Unlock()
	m.LatestHytale()
	waitFor(t, s, "update offered", func(st Status) bool { return st.UpdateTo == "2026.10.08-bbbb222" })
	if err := s.Update(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, "updated", func(st Status) bool { return st.Version == "2026.10.08-bbbb222" && st.State == StateRunning })
	if got := readFile(t, filepath.Join(s.dir(), hytaleJar)); got != "hytale server 2026.10.08-bbbb222" {
		t.Errorf("jar: %q", got)
	}
	var before *Backup
	for _, b := range s.Backups().Backups {
		if b.Kind == "before-update" {
			before = &b
		}
	}
	if before == nil {
		t.Fatal("no backup before the update")
	}
	if c := tarContents(t, filepath.Join(m.backupsDir(s.ID()), before.Name)); c[hytaleAssets] != "" || c["universe/worlds/default/config.json"] == "" {
		t.Errorf("before-update backup has %v", keys(c))
	}

	// Not offered to consoles.
	for _, j := range m.Joinable() {
		if j.Port == st.Port {
			t.Error("Hytale server in the console list")
		}
	}
	if _, err := s.Packs(); err == nil {
		t.Error("add-ons on a Hytale server")
	}
	if _, err := s.Plugins(); err == nil {
		t.Error("Java plugins on a Hytale server")
	}

	// Signed out: it won't start, and says why.
	if err := m.SignOutHytale(); err != nil {
		t.Fatal(err)
	}
	if err := s.Restart(); err == nil || s.Status().State != StateRunning {
		t.Error("restarted without a Hytale sign-in (or stopped trying)")
	}
	s.Stop()
	waitFor(t, s, "stopped", state(StateStopped))
	if err := s.Start(); err == nil {
		t.Error("started without a Hytale sign-in")
	}
	if st := s.Status(); st.State != StateError || !strings.Contains(st.Message, "Hytale") {
		t.Errorf("status: %+v", st)
	}
}

func TestHytaleLines(t *testing.T) {
	for line, want := range map[string]string{
		"[2026/01/13 12:00:00   INFO]   [HandshakeHandler] Mutual authentication complete for Steve (0a0a0a0a-0000-0000-0000-000000000001) from x (/1.2.3.4:5, streamId=1)": "join Steve",
		"[2026/01/13 12:00:00   INFO]   [Universe|P] Removing player 'Steve' (0a0a0a0a-0000-0000-0000-000000000001)":                                                        "leave Steve",
		"[2026/01/13 12:00:00   INFO]   [Hytale] {Setup(null (null, streamId=3)), Steve, 0a0a0a0a-0000-0000-0000-000000000001, SECURE} was closed.":                         "leave Steve",
		"[2026/01/13 12:00:00   INFO]   [Hytale] Bob: [HandshakeHandler] Mutual authentication complete for Steve (0a0a0a0a-0000-0000-0000-000000000001)":                   "",
		"[2026/01/13 12:00:00   INFO]   [Hytale] Bob: [Universe|P] Removing player 'Steve' (0a0a0a0a-0000-0000-0000-000000000001)":                                          "",
	} {
		got := ""
		if m := reHytaleJoin.FindStringSubmatch(line); m != nil {
			got = "join " + m[1]
		} else if m := reHytaleLeave.FindStringSubmatch(line); m != nil {
			got = "leave " + m[1] + m[3]
		}
		if got != want {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}
	if !reHytaleBooted.MatchString("[2026/01/13 12:00:00   INFO]   [HytaleServer] Hytale Server Booted! [Multiplayer] took 3s") ||
		reHytaleBooted.MatchString("[2026/01/13 12:00:00   INFO]   [Hytale] Bob: [HytaleServer] Hytale Server Booted!") {
		t.Error("booted line")
	}
	if !hytaleNewer("2026.10.08-b", "2026.10.01-a") || hytaleNewer("2026.10.01-a", "2026.10.08-b") || hytaleNewer("x", "x") || !hytaleNewer("2026.01.01-a", "") {
		t.Error("hytaleNewer")
	}
}

// When Hytale's sessions service is down, a restart leaves the server
// running, and a crashed server keeps trying until it's back.
func TestHytaleSessionOutage(t *testing.T) {
	f := newFakeHytale(t)
	m := newHytaleManager(t, f)
	old, oldBackoff := hytaleRetryEvery, crashBackoff
	hytaleRetryEvery, crashBackoff = 50*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { hytaleRetryEvery, crashBackoff = old, oldBackoff })
	signInHytale(t, m)
	st, err := m.CreateHytale("Outage", 0)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := m.Get(st.ID)
	waitFor(t, s, "running", state(StateRunning))
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	if err := s.Restart(); err == nil {
		t.Error("restarted without a session")
	}
	if s.Status().State != StateRunning {
		t.Error("the restart stopped it")
	}
	// It crashes while the service is down: it waits, then comes back.
	s.mu.Lock()
	pid := s.cmd.Process.Pid
	s.mu.Unlock()
	syscallKill(pid)
	waitConsole(t, s, "trying again in a minute")
	if s.Status().State == StateError {
		t.Error("gave up")
	}
	f.mu.Lock()
	f.down = false
	f.mu.Unlock()
	waitFor(t, s, "running again", state(StateRunning))

	// Started (by hand, or as the panel starts) while it's down: it waits.
	s.Stop()
	waitFor(t, s, "stopped", state(StateStopped))
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.State != StateStarting || !strings.Contains(st.Message, "waiting for Hytale") {
		t.Errorf("status: %+v", st)
	}
	f.mu.Lock()
	f.down = false
	f.mu.Unlock()
	waitFor(t, s, "running once it's back", state(StateRunning))
}

func syscallKill(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) }
