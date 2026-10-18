package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Checking for a newer Block Party. The panel looks at the project's
// release tags on GitHub now and then, and the owner sees a notice when
// there's a newer release than the one running. Nothing is downloaded or
// installed: updating is Unraid's job (Apply update on the Docker tab).

// panelUpdateURL lists the project's tags (PANEL_UPDATE_API replaces it, for
// tests; "off" turns checking off).
const panelUpdateURL = "https://api.github.com/repos/ScottSchneck/block-party/tags?per_page=100"

// panelUpdateEvery is how often the panel looks again.
const panelUpdateEvery = 12 * time.Hour

var reRelease = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// releaseNumbers turns "v1.2.3" into [1 2 3]; ok is false for anything that
// isn't a plain release ("dev", "main-abc1234", "v1.2.0-rc1").
func releaseNumbers(v string) (n [3]int, ok bool) {
	m := reRelease.FindStringSubmatch(v)
	if m == nil {
		return n, false
	}
	for i := range 3 {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	return n, true
}

func releaseNewer(a, b [3]int) bool {
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// panelUpdate remembers the newest release seen.
type panelUpdate struct {
	mu      sync.Mutex
	latest  string // newest release tag, "" until known
	checked time.Time
}

func (p *panelUpdate) get() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.latest
}

// newerPanel is the newest release when it's newer than this panel, or "".
// A panel that isn't a release build (dev, edge) never hears of updates.
func (s *Server) newerPanel() string {
	cur, ok := releaseNumbers(s.opts.Version)
	if !ok {
		return ""
	}
	latest := s.update.get()
	if n, ok := releaseNumbers(latest); ok && releaseNewer(n, cur) {
		return latest
	}
	return ""
}

// checkPanelUpdates looks for a newer release until ctx ends.
func (s *Server) checkPanelUpdates(ctx context.Context) {
	url := os.Getenv("PANEL_UPDATE_API")
	if url == "off" {
		return
	}
	if url == "" {
		url = panelUpdateURL
	}
	if _, ok := releaseNumbers(s.opts.Version); !ok {
		return // a test build: nothing to compare with
	}
	wait := time.Minute // let the panel settle first
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		latest, err := fetchLatestRelease(ctx, url)
		wait = panelUpdateEvery
		if err != nil {
			s.log.Debug("couldn't check for a newer Block Party", "error", err)
			wait = time.Hour
			continue
		}
		s.update.mu.Lock()
		changed := latest != s.update.latest
		s.update.latest, s.update.checked = latest, time.Now()
		s.update.mu.Unlock()
		if changed && s.newerPanel() != "" {
			s.log.Info("a newer Block Party is out", "running", s.opts.Version, "latest", latest)
		}
	}
}

// fetchLatestRelease returns the newest plain release tag at url (GitHub's
// tags list).
func fetchLatestRelease(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "block-party")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", res.Status)
	}
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, res.Body, 1<<20)).Decode(&tags); err != nil {
		return "", err
	}
	best, bestN := "", [3]int{}
	for _, t := range tags {
		if n, ok := releaseNumbers(t.Name); ok && (best == "" || releaseNewer(n, bestN)) {
			best, bestN = t.Name, n
		}
	}
	if best == "" {
		return "", fmt.Errorf("no releases listed")
	}
	return best, nil
}
