package servers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The Hytale account. Hytale's server files are only downloaded by a signed-in
// Hytale account, and a Hytale server needs a signed-in session for players to
// join. The owner signs in once here (Hytale's "device code" sign-in, twice:
// once for downloads and once for servers, as Hytale's own tools do), and the
// panel keeps the sign-in fresh and gives each Hytale server a session when it
// starts. This follows Hytale's Server Provider Authentication Guide.

// Default addresses of Hytale's services.
const (
	DefaultHytaleOAuth    = "https://oauth.accounts.hytale.com"
	DefaultHytaleAccounts = "https://account-data.hytale.com"
	DefaultHytaleSessions = "https://sessions.hytale.com"
)

// The two sign-ins: one to download the server, one to run it.
type hytaleClient struct {
	id, scope, label string
}

var (
	hytaleDownloaderClient = hytaleClient{"hytale-downloader", "offline auth:downloader", "downloads"}
	hytaleServerClient     = hytaleClient{"hytale-server", "openid offline auth:server", "servers"}
)

type hytaleTokens struct {
	Access    string    `json:"access"`
	Refresh   string    `json:"refresh"`
	Expires   time.Time `json:"expires"`
	Refreshed time.Time `json:"refreshed"` // when it was last refreshed (or signed in)
}

// hytaleAccount is kept in <data>/hytale-account.json (readable only by the
// panel).
type hytaleAccount struct {
	Downloader  hytaleTokens `json:"downloader"`
	Server      hytaleTokens `json:"server"`
	ProfileUUID string       `json:"profileUuid"`
	Username    string       `json:"username"`
	RefreshedAt time.Time    `json:"refreshedAt"`
}

func (a *hytaleAccount) signedIn() bool {
	return a != nil && a.Downloader.Refresh != "" && a.Server.Refresh != "" && a.ProfileUUID != ""
}

// HytaleSignIn is a sign-in in progress: open URL and enter Code.
type HytaleSignIn struct {
	Step    int       `json:"step"` // 1 (downloads) or 2 (servers)
	Of      int       `json:"of"`
	For     string    `json:"for"`
	URL     string    `json:"url"`
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

// HytaleAccountView is the Hytale account card.
type HytaleAccountView struct {
	SignedIn bool          `json:"signedIn"`
	Username string        `json:"username,omitempty"`
	Pending  *HytaleSignIn `json:"pending,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// hytaleAuth is the Manager's Hytale account state.
type hytaleAuth struct {
	mu      sync.Mutex // guards the fields and the file
	loaded  bool
	account *hytaleAccount
	pending *HytaleSignIn
	cancel  context.CancelFunc
	err     string
}

func (m *Manager) hytaleAccountPath() string {
	return filepath.Join(m.opts.DataDir, "hytale-account.json")
}

// loadHytaleLocked reads the saved account once. Caller holds h.mu.
func (m *Manager) loadHytaleLocked() {
	h := &m.hytale
	if h.loaded {
		return
	}
	h.loaded = true
	b, err := os.ReadFile(m.hytaleAccountPath())
	if err != nil {
		return
	}
	var a hytaleAccount
	if json.Unmarshal(b, &a) == nil && a.signedIn() {
		h.account = &a
	}
}

// saveHytaleLocked writes the account. Caller holds h.mu.
func (m *Manager) saveHytaleLocked() error {
	h := &m.hytale
	path := m.hytaleAccountPath()
	if h.account == nil {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, err := json.MarshalIndent(h.account, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// HytaleAccount returns the Hytale account card.
func (m *Manager) HytaleAccount() HytaleAccountView {
	h := &m.hytale
	h.mu.Lock()
	defer h.mu.Unlock()
	m.loadHytaleLocked()
	v := HytaleAccountView{Error: h.err}
	if h.account.signedIn() {
		v.SignedIn, v.Username = true, h.account.Username
	}
	if h.pending != nil {
		p := *h.pending
		v.Pending = &p
	}
	return v
}

// hytaleOwnerUUID is the signed-in profile's account ID ("" if none).
func (m *Manager) hytaleOwnerUUID() string {
	h := &m.hytale
	h.mu.Lock()
	defer h.mu.Unlock()
	m.loadHytaleLocked()
	if !h.account.signedIn() {
		return ""
	}
	return h.account.ProfileUUID
}

// HytaleSignedIn reports whether a Hytale account is signed in.
func (m *Manager) HytaleSignedIn() bool { return m.HytaleAccount().SignedIn }

// StartHytaleSignIn begins signing in (or returns the sign-in already in
// progress). Follow it with HytaleAccount.
func (m *Manager) StartHytaleSignIn() (HytaleAccountView, error) {
	h := &m.hytale
	h.mu.Lock()
	if h.pending != nil {
		h.mu.Unlock()
		return m.HytaleAccount(), nil
	}
	if !m.beginWork() {
		h.mu.Unlock()
		return HytaleAccountView{}, errShuttingDown
	}
	ctx, cancel := context.WithTimeout(m.ctx, 40*time.Minute)
	h.cancel, h.err = cancel, ""
	h.pending = &HytaleSignIn{Step: 1, Of: 2, For: hytaleDownloaderClient.label}
	h.mu.Unlock()

	first := make(chan struct{})
	go func() {
		defer m.work.Done()
		defer cancel()
		err := m.hytaleSignIn(ctx, first)
		h.mu.Lock()
		h.pending, h.cancel = nil, nil
		if err != nil {
			h.err = err.Error()
			m.log.Warn("hytale sign-in failed", "error", err)
		}
		h.mu.Unlock()
		select {
		case <-first:
		default:
			close(first)
		}
	}()
	select { // the first code, so the page can show it straight away
	case <-first:
	case <-time.After(15 * time.Second):
	}
	return m.HytaleAccount(), nil
}

// CancelHytaleSignIn stops a sign-in in progress.
func (m *Manager) CancelHytaleSignIn() {
	h := &m.hytale
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cancel != nil {
		h.cancel()
	}
}

// SignOutHytale forgets the Hytale account.
func (m *Manager) SignOutHytale() error {
	h := &m.hytale
	h.mu.Lock()
	defer h.mu.Unlock()
	m.loadHytaleLocked()
	if h.cancel != nil {
		h.cancel()
	}
	h.account, h.err = nil, ""
	return m.saveHytaleLocked()
}

func (m *Manager) hytaleSignIn(ctx context.Context, first chan struct{}) error {
	h := &m.hytale
	var a hytaleAccount
	for i, c := range []hytaleClient{hytaleDownloaderClient, hytaleServerClient} {
		show := func(uri, code string, expires time.Time) {
			h.mu.Lock()
			h.pending = &HytaleSignIn{Step: i + 1, Of: 2, For: c.label, URL: uri, Code: code, Expires: expires}
			h.mu.Unlock()
			if i == 0 {
				close(first)
			}
		}
		t, err := m.hytaleDeviceFlow(ctx, c, show)
		if err != nil {
			return err
		}
		if i == 0 {
			a.Downloader = t
		} else {
			a.Server = t
		}
	}
	uuid, name, err := m.hytaleProfile(ctx, a.Server.Access)
	if err != nil {
		return err
	}
	a.ProfileUUID, a.Username, a.RefreshedAt = uuid, name, time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return errors.New("the sign-in was stopped")
	}
	h.account = &a
	m.log.Info("signed in to hytale", "username", name)
	return m.saveHytaleLocked()
}

// hytalePost posts a form to Hytale's sign-in service.
func (m *Manager) hytalePost(ctx context.Context, path string, form url.Values, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.opts.HytaleOAuth+path, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", m.javaUserAgent())
	resp, err := m.http().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

type oauthAnswer struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

func (o oauthAnswer) tokens() hytaleTokens {
	exp := o.ExpiresIn
	if exp <= 0 {
		exp = 3600
	}
	return hytaleTokens{Access: o.AccessToken, Refresh: o.RefreshToken, Expires: time.Now().Add(time.Duration(exp) * time.Second), Refreshed: time.Now()}
}

// hytaleDeviceFlow signs in one client: it shows a code, then waits until
// the owner has entered it.
func (m *Manager) hytaleDeviceFlow(ctx context.Context, c hytaleClient, show func(uri, code string, expires time.Time)) (hytaleTokens, error) {
	var d struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		URI        string `json:"verification_uri"`
		URIFull    string `json:"verification_uri_complete"`
		ExpiresIn  int    `json:"expires_in"`
		Interval   int    `json:"interval"`
	}
	status, err := m.hytalePost(ctx, "/oauth2/device/auth", url.Values{"client_id": {c.id}, "scope": {c.scope}}, &d)
	if err != nil {
		return hytaleTokens{}, fmt.Errorf("couldn't reach Hytale's sign-in: %w", err)
	}
	if status != http.StatusOK || d.DeviceCode == "" || d.UserCode == "" {
		return hytaleTokens{}, fmt.Errorf("Hytale's sign-in answered %d", status)
	}
	uri := d.URIFull
	if uri == "" {
		uri = d.URI
	}
	if !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(m.opts.HytaleOAuth, "http://127.") {
		return hytaleTokens{}, errors.New("Hytale's sign-in gave an odd address")
	}
	if d.ExpiresIn <= 0 {
		d.ExpiresIn = 900
	}
	interval := time.Duration(d.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if hytalePollEvery > 0 {
		interval = hytalePollEvery
	}
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	show(uri, d.UserCode, deadline)
	for {
		select {
		case <-ctx.Done():
			return hytaleTokens{}, errors.New("the sign-in was stopped")
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return hytaleTokens{}, errors.New("the code ran out before it was entered; sign in again")
		}
		var t oauthAnswer
		status, err := m.hytalePost(ctx, "/oauth2/token", url.Values{
			"client_id":   {c.id},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {d.DeviceCode},
		}, &t)
		if err != nil {
			continue // a network blip: keep waiting
		}
		switch t.Error {
		case "":
			if status == http.StatusOK && t.AccessToken != "" && t.RefreshToken != "" {
				return t.tokens(), nil
			}
			return hytaleTokens{}, fmt.Errorf("Hytale's sign-in answered %d", status)
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return hytaleTokens{}, errors.New("the sign-in was turned down on Hytale's page")
		case "expired_token":
			return hytaleTokens{}, errors.New("the code ran out before it was entered; sign in again")
		default:
			return hytaleTokens{}, fmt.Errorf("Hytale's sign-in said %s %s", t.Error, t.Description)
		}
	}
}

// hytalePollEvery shortens the wait between checks in tests.
var hytalePollEvery time.Duration

// hytaleToken returns a fresh access token for downloads or servers,
// refreshing it (and saving the new refresh token, which replaces the old
// one) when it's about to run out.
func (m *Manager) hytaleToken(ctx context.Context, c hytaleClient) (string, error) {
	t, _, err := m.hytaleTokenAndOwner(ctx, c)
	return t, err
}

// hytaleTokenAndOwner is hytaleToken, with the signed-in profile's ID.
func (m *Manager) hytaleTokenAndOwner(ctx context.Context, c hytaleClient) (string, string, error) {
	h := &m.hytale
	h.mu.Lock()
	defer h.mu.Unlock()
	m.loadHytaleLocked()
	if !h.account.signedIn() {
		return "", "", ErrHytaleSignIn
	}
	owner := h.account.ProfileUUID
	t := &h.account.Downloader
	if c == hytaleServerClient {
		t = &h.account.Server
	}
	if t.Access != "" && time.Until(t.Expires) > 2*time.Minute {
		return t.Access, owner, nil
	}
	if err := m.refreshHytaleLocked(ctx, c, t); err != nil {
		return "", "", err
	}
	return t.Access, owner, nil
}

// ErrHytaleSignIn means nobody is signed in to Hytale (or the sign-in ran
// out).
var ErrHytaleSignIn = errors.New("the panel isn't signed in to a Hytale account; the owner signs in under Add server, Hytale")

// refreshHytaleLocked refreshes one sign-in. Caller holds h.mu (the call
// is short, and refreshes must not overlap: each one replaces the token).
func (m *Manager) refreshHytaleLocked(ctx context.Context, c hytaleClient, t *hytaleTokens) error {
	// A refresh replaces the refresh token, so it isn't cut off halfway by
	// the caller giving up (the answer would be lost with the new token).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var a oauthAnswer
	status, err := m.hytalePost(ctx, "/oauth2/token", url.Values{
		"client_id":     {c.id},
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.Refresh},
	}, &a)
	if err != nil {
		return fmt.Errorf("couldn't reach Hytale's sign-in: %w", err)
	}
	if a.Error == "invalid_grant" || status == http.StatusUnauthorized {
		// This sign-in ran out; the other may still work, but both are
		// needed, so the owner signs in again.
		h := &m.hytale
		*t = hytaleTokens{}
		h.err = "The Hytale sign-in for " + c.label + " ran out (it lasts 30 days without use). Sign in again."
		_ = m.saveHytaleLocked()
		return ErrHytaleSignIn
	}
	if status != http.StatusOK || a.AccessToken == "" {
		return fmt.Errorf("Hytale's sign-in answered %d %s", status, a.Error)
	}
	nt := a.tokens()
	if nt.Refresh == "" {
		nt.Refresh = t.Refresh
	}
	*t = nt
	m.hytale.account.RefreshedAt = time.Now()
	return m.saveHytaleLocked()
}

// hytaleProfile returns the account's first game profile.
func (m *Manager) hytaleProfile(ctx context.Context, access string) (uuid, name string, err error) {
	var p struct {
		Owner    string `json:"owner"`
		Profiles []struct {
			UUID     string `json:"uuid"`
			Username string `json:"username"`
			Name     string `json:"name"`
		} `json:"profiles"`
	}
	if err := m.hytaleGet(ctx, m.opts.HytaleAccounts+"/my-account/get-profiles", access, &p); err != nil {
		return "", "", fmt.Errorf("couldn't read the Hytale account: %w", err)
	}
	if len(p.Profiles) == 0 || p.Profiles[0].UUID == "" {
		return "", "", errors.New("that Hytale account has no game profile (does it own Hytale?)")
	}
	name = p.Profiles[0].Username
	if name == "" {
		name = p.Profiles[0].Name
	}
	return p.Profiles[0].UUID, name, nil
}

func (m *Manager) hytaleGet(ctx context.Context, u, access string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("User-Agent", m.javaUserAgent())
	resp, err := m.http().Do(req)
	if err != nil {
		return plainErr(u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", hostOf(u), resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// hytaleSession is what a Hytale server is started with.
type hytaleSession struct {
	Session, Identity, Owner string
}

// newHytaleSession creates a game session for a server that's starting. The
// server refreshes it by itself while it runs.
func (m *Manager) newHytaleSession(ctx context.Context) (hytaleSession, error) {
	access, owner, err := m.hytaleTokenAndOwner(ctx, hytaleServerClient)
	if err != nil {
		return hytaleSession{}, err
	}
	body, _ := json.Marshal(map[string]string{"uuid": owner})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.opts.HytaleSessions+"/game-session/new", strings.NewReader(string(body)))
	if err != nil {
		return hytaleSession{}, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", m.javaUserAgent())
	resp, err := m.http().Do(req)
	if err != nil {
		return hytaleSession{}, fmt.Errorf("couldn't reach Hytale's sessions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return hytaleSession{}, errors.New("Hytale refused another server session for this account (the limit is 500)")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return hytaleSession{}, fmt.Errorf("Hytale's sessions answered %s", resp.Status)
	}
	var s struct {
		SessionToken  string `json:"sessionToken"`
		IdentityToken string `json:"identityToken"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s); err != nil {
		return hytaleSession{}, err
	}
	if s.SessionToken == "" || s.IdentityToken == "" {
		return hytaleSession{}, errors.New("Hytale's sessions gave an odd answer")
	}
	return hytaleSession{Session: s.SessionToken, Identity: s.IdentityToken, Owner: owner}, nil
}

// RunHytaleKeepAlive refreshes the Hytale sign-in about once a week, so it
// doesn't run out (it lasts 30 days unused) while no Hytale server starts.
func (m *Manager) RunHytaleKeepAlive() {
	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-t.C:
			}
			m.hytaleKeepAlive()
		}
	}()
}

func (m *Manager) hytaleKeepAlive() {
	h := &m.hytale
	h.mu.Lock()
	defer h.mu.Unlock()
	m.loadHytaleLocked()
	if !h.account.signedIn() {
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()
	for _, c := range []hytaleClient{hytaleDownloaderClient, hytaleServerClient} {
		if !h.account.signedIn() {
			return
		}
		t := &h.account.Downloader
		if c == hytaleServerClient {
			t = &h.account.Server
		}
		if time.Since(t.Refreshed) < 7*24*time.Hour {
			continue
		}
		if err := m.refreshHytaleLocked(ctx, c, t); err != nil {
			m.log.Warn("couldn't refresh the hytale sign-in", "error", err)
			return
		}
	}
}
