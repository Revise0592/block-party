package playit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// AgentVersion is the playit agent the panel downloads. It's pinned, and
// checked against the hashes below, so what runs never changes underneath
// the panel. To move to a newer one, take the release's assets from
// https://github.com/playit-cloud/playit-agent/releases and put their
// sha256 here.
const AgentVersion = "1.0.12"

var agentBuilds = map[string]struct{ asset, sha256 string }{
	"amd64": {"playit-linux-amd64", "4ad5aa85670e056b2d2f5f47f9f992b81db34bedc89bbe755c6f8cc0c8206c78"},
	"arm64": {"playit-linux-aarch64", "01ed32ab8f9bd15120a9adfbba866346687f7874398023458f8035997bd4e617"},
}

// agentURL is where a release asset is downloaded from (tests change it).
var agentURL = func(asset string) string {
	return "https://github.com/playit-cloud/playit-agent/releases/download/v" + AgentVersion + "/" + asset
}

// ensureAgent downloads the agent once and returns its path.
func ensureAgent(ctx context.Context, dir string) (string, error) {
	b, ok := agentBuilds[runtime.GOARCH]
	if runtime.GOOS != "linux" || !ok {
		return "", fmt.Errorf("playit.gg's agent isn't available for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	path := filepath.Join(dir, "playit-"+AgentVersion)
	if sum, err := fileSHA256(path); err == nil && sum == b.sha256 {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentURL(b.asset), nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("couldn't download playit.gg's agent: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("couldn't download playit.gg's agent: %s", resp.Status)
	}
	// Written without the execute bit, and only made runnable once the hash
	// matches.
	tmp := path + ".download"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 64<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("couldn't download playit.gg's agent: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != b.sha256 {
		os.Remove(tmp)
		return "", fmt.Errorf("the downloaded playit.gg agent isn't the expected file (sha256 %s); not running it", got)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	// Older versions aren't needed any more.
	if old, _ := filepath.Glob(filepath.Join(dir, "playit-*")); len(old) > 0 {
		for _, o := range old {
			if o != path && !strings.HasSuffix(o, ".download") {
				os.Remove(o)
			}
		}
	}
	return path, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Agent states.
const (
	AgentStopped  = "stopped"
	AgentStarting = "starting"
	AgentRunning  = "running"
	AgentWaiting  = "waiting" // it stopped and is started again shortly
)

const agentLogLines = 40

var reANSI = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

// agent keeps one playit agent process running while it's wanted, starting
// it again (with growing pauses) when it stops.
type agent struct {
	log *slog.Logger

	mu      sync.Mutex
	args    []string // what it runs with; nil while it isn't wanted
	cmd     *exec.Cmd
	done    chan struct{} // closed when the running loop ends
	stop    chan struct{}
	state   string
	lastErr string
	lines   []string
}

func newAgent(log *slog.Logger) *agent { return &agent{log: log, state: AgentStopped} }

// run makes sure the agent runs with these arguments (path first).
func (a *agent) run(args []string) {
	a.mu.Lock()
	if a.args != nil && slices.Equal(a.args, args) {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	a.halt()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.args = args
	a.stop = make(chan struct{})
	a.done = make(chan struct{})
	a.state = AgentStarting
	go a.loop(args, a.stop, a.done)
}

// halt stops the agent and waits for it.
func (a *agent) halt() {
	a.mu.Lock()
	if a.args == nil {
		a.mu.Unlock()
		return
	}
	a.args = nil
	close(a.stop)
	cmd, done := a.cmd, a.done
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	a.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		a.mu.Lock()
		cmd = a.cmd
		a.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}
	a.mu.Lock()
	a.state = AgentStopped
	a.mu.Unlock()
}

func (a *agent) loop(args []string, stop, done chan struct{}) {
	defer close(done)
	pause := 5 * time.Second
	for {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "NO_COLOR=1", "RUST_LOG=info")
		out, err := cmd.StdoutPipe()
		if err == nil {
			cmd.Stderr = cmd.Stdout
			err = cmd.Start()
		}
		started := time.Now()
		if err != nil {
			a.mu.Lock()
			a.lastErr = "couldn't start playit.gg's agent: " + err.Error()
			a.mu.Unlock()
		} else {
			a.mu.Lock()
			a.cmd = cmd
			a.state = AgentRunning
			a.mu.Unlock()
			select {
			case <-stop: // halted while it was starting
				_ = cmd.Process.Signal(syscall.SIGTERM)
			default:
			}
			a.log.Info("playit.gg agent started", "version", AgentVersion)
			sc := bufio.NewScanner(out)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				a.addLine(sc.Text())
			}
			werr := cmd.Wait()
			a.mu.Lock()
			a.cmd = nil
			if werr != nil {
				a.lastErr = "playit.gg's agent stopped: " + werr.Error()
			} else {
				a.lastErr = "playit.gg's agent stopped"
			}
			a.mu.Unlock()
		}
		select {
		case <-stop:
			return
		default:
		}
		if time.Since(started) > 2*time.Minute {
			pause = 5 * time.Second
		}
		a.mu.Lock()
		a.state = AgentWaiting
		msg := a.lastErr
		a.mu.Unlock()
		a.log.Warn(msg+"; starting it again", "in", pause)
		select {
		case <-stop:
			return
		case <-time.After(pause):
		}
		pause = min(pause*2, time.Minute)
		a.mu.Lock()
		a.state = AgentStarting
		a.mu.Unlock()
	}
}

func (a *agent) addLine(line string) {
	line = strings.TrimSpace(reANSI.ReplaceAllString(line, ""))
	if line == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = append(a.lines, line)
	if len(a.lines) > agentLogLines {
		a.lines = append([]string(nil), a.lines[len(a.lines)-agentLogLines:]...)
	}
}

// status says how the agent is doing, with its latest lines.
func (a *agent) status() (state, lastErr string, lines []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == AgentRunning {
		lastErr = ""
	} else {
		lastErr = a.lastErr
	}
	return a.state, lastErr, append([]string(nil), a.lines...)
}

func (a *agent) clearLog() {
	a.mu.Lock()
	a.lines = nil
	a.lastErr = ""
	a.mu.Unlock()
}
