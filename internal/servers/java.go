package servers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Java Edition servers run Paper (papermc.io), a faster Minecraft Java
// server that also runs plugins. Java itself is downloaded the first time a
// server needs it (Eclipse Temurin, from adoptium.net) into
// <data>/runtimes/java-<version>, so the container image stays small and
// each Minecraft version gets the Java it needs.
//
// A Java server keeps its worlds in worlds/ like a Bedrock one (Paper is
// started with --world-container worlds), so backups, restores and world
// switching work the same way.

// Type values for Meta.Type.
const (
	TypeBedrock = "bedrock"
	TypeJava    = "java"
)

// Default addresses of the services Java servers are installed from.
const (
	DefaultPaperAPI      = "https://fill.papermc.io/v3/projects/paper"
	DefaultAdoptiumAPI   = "https://api.adoptium.net/v3"
	DefaultMojangVersion = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
	DefaultMojangProfile = "https://api.mojang.com/users/profiles/minecraft/"
)

const (
	paperJar         = "paper.jar"
	defaultMemoryMB  = 2048
	javaWorldDefault = "world"
)

func (s *Server) isJava() bool { return s.meta.Type == TypeJava }

// javaUserAgent identifies the panel to PaperMC, which asks for a contact.
func (m *Manager) javaUserAgent() string {
	return "BlockheadsControlPanel/" + m.opts.Version + " (https://github.com/ScottSchneck/blockheads-control-panel)"
}

func (m *Manager) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", m.javaUserAgent())
	req.Header.Set("Accept", "application/json")
	resp, err := m.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", hostOf(url), resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

func jsonDecodeLimited(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(v)
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

// ---- Paper ----

// PaperRelease is a Paper build.
type PaperRelease struct {
	Version string // Minecraft version, e.g. 1.21.4
	Build   int
	URL     string
	SHA256  string
}

func (r PaperRelease) label() string {
	return fmt.Sprintf("%s (Paper build %d)", r.Version, r.Build)
}

var plainVersion = regexp.MustCompile(`^\d+(\.\d+){1,3}$`)

type paperBuild struct {
	ID        int    `json:"id"`
	Channel   string `json:"channel"`
	Downloads map[string]struct {
		Name      string            `json:"name"`
		URL       string            `json:"url"`
		Checksums map[string]string `json:"checksums"`
	} `json:"downloads"`
}

// latestPaper returns the newest stable Paper build of the newest Minecraft
// version that has one.
func (m *Manager) latestPaper(ctx context.Context) (PaperRelease, error) {
	var project struct {
		Versions map[string][]string `json:"versions"`
	}
	if err := m.getJSON(ctx, m.opts.PaperAPI, &project); err != nil {
		return PaperRelease{}, fmt.Errorf("couldn't ask PaperMC for its versions: %w", err)
	}
	var versions []string
	for _, group := range project.Versions {
		for _, v := range group {
			if plainVersion.MatchString(v) { // no pre-releases
				versions = append(versions, v)
			}
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versionNewer(versions[i], versions[j]) })
	for i, v := range versions {
		if i >= 4 {
			break // the newest few are enough to find one with a stable build
		}
		var builds []paperBuild
		if err := m.getJSON(ctx, m.opts.PaperAPI+"/versions/"+v+"/builds", &builds); err != nil {
			return PaperRelease{}, fmt.Errorf("couldn't ask PaperMC for its builds: %w", err)
		}
		best := -1
		for bi, b := range builds {
			if strings.EqualFold(b.Channel, "STABLE") && (best < 0 || b.ID > builds[best].ID) {
				best = bi
			}
		}
		if best < 0 {
			continue
		}
		d, ok := builds[best].Downloads["server:default"]
		if !ok || d.URL == "" {
			continue
		}
		return PaperRelease{Version: v, Build: builds[best].ID, URL: d.URL, SHA256: strings.ToLower(d.Checksums["sha256"])}, nil
	}
	return PaperRelease{}, errors.New("PaperMC doesn't have a stable build yet")
}

// paperCache keeps the newest Paper release for "update ready" notes.
type paperCache struct {
	mu      sync.Mutex
	release PaperRelease
	at      time.Time
	busy    bool
}

// LatestPaper returns the newest Paper release, checking at most once an
// hour, without waiting (like LatestRelease).
func (m *Manager) LatestPaper() PaperRelease {
	c := &m.paper
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.busy && time.Since(c.at) > versionCheckEvery {
		c.busy = true
		go func() {
			ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
			defer cancel()
			r, err := m.latestPaper(ctx)
			c.mu.Lock()
			defer c.mu.Unlock()
			c.busy, c.at = false, time.Now()
			if err == nil {
				c.release = r
			}
		}()
	}
	return c.release
}

// javaNewer reports whether release r is newer than a server's version and
// build.
func javaNewer(r PaperRelease, version string, build int) bool {
	if r.Version == "" {
		return false
	}
	if r.Version != version {
		return versionNewer(r.Version, version)
	}
	return r.Build > build
}

// ---- Java runtime ----

// javaMajorFor returns the Java version a Minecraft version needs, asking
// Mojang, or guessing from the version number if Mojang can't be reached.
func (m *Manager) javaMajorFor(ctx context.Context, mc string) int {
	var manifest struct {
		Versions []struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"versions"`
	}
	if err := m.getJSON(ctx, m.opts.MojangVersions, &manifest); err == nil {
		for _, v := range manifest.Versions {
			if v.ID != mc {
				continue
			}
			var info struct {
				JavaVersion struct {
					MajorVersion int `json:"majorVersion"`
				} `json:"javaVersion"`
			}
			if err := m.getJSON(ctx, v.URL, &info); err == nil && info.JavaVersion.MajorVersion >= 8 {
				return info.JavaVersion.MajorVersion
			}
		}
	}
	switch {
	case !versionNewer("26", mc): // 26.1 and later (the yearly versions)
		return 25
	case !versionNewer("1.20.5", mc):
		return 21
	case !versionNewer("1.18", mc):
		return 17
	}
	return 17
}

func (m *Manager) runtimesDir() string { return filepath.Join(m.opts.DataDir, "runtimes") }

// javaBinary returns the java program of an installed runtime ("" if not
// installed).
func (m *Manager) javaBinary(major int) string {
	p := filepath.Join(m.runtimesDir(), "java-"+strconv.Itoa(major), "bin", "java")
	if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
		return p
	}
	return ""
}

// ensureJava installs a Java runtime if it isn't there yet. Only one install
// of each version runs at a time.
func (m *Manager) ensureJava(ctx context.Context, major int, say func(string)) (string, error) {
	m.javaMu.Lock()
	defer m.javaMu.Unlock()
	if bin := m.javaBinary(major); bin != "" {
		return bin, nil
	}
	arch := map[string]string{"amd64": "x64", "arm64": "aarch64"}[runtime.GOARCH]
	if arch == "" {
		return "", fmt.Errorf("Java servers aren't supported on %s", runtime.GOARCH)
	}
	say(fmt.Sprintf("Downloading Java %d (Eclipse Temurin), needed once for Java servers…", major))
	var assets []struct {
		Binary struct {
			Package struct {
				Link     string `json:"link"`
				Checksum string `json:"checksum"`
				Size     int64  `json:"size"`
			} `json:"package"`
		} `json:"binary"`
		ReleaseName string `json:"release_name"`
	}
	url := fmt.Sprintf("%s/assets/latest/%d/hotspot?architecture=%s&image_type=jre&os=linux&vendor=eclipse", m.opts.AdoptiumAPI, major, arch)
	if err := m.getJSON(ctx, url, &assets); err != nil {
		return "", fmt.Errorf("couldn't find Java %d to download: %w", major, err)
	}
	if len(assets) == 0 || assets[0].Binary.Package.Link == "" {
		return "", fmt.Errorf("adoptium.net has no Java %d for this computer", major)
	}
	pkg := assets[0].Binary.Package
	if err := os.MkdirAll(m.runtimesDir(), 0o755); err != nil {
		return "", err
	}
	file, err := m.downloadVerified(ctx, pkg.Link, m.runtimesDir(), pkg.Checksum, say, m.javaUserAgent())
	if err != nil {
		return "", err
	}
	defer os.Remove(file)
	staging, err := os.MkdirTemp(m.runtimesDir(), ".java-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	err = extractTarGz(ctx, f, staging)
	f.Close()
	if err != nil {
		return "", fmt.Errorf("couldn't unpack Java: %w", err)
	}
	// The archive has one top folder (jdk-25.0.1+8-jre); that becomes java-25.
	entries, _ := os.ReadDir(staging)
	root := staging
	if len(entries) == 1 && entries[0].IsDir() {
		root = filepath.Join(staging, entries[0].Name())
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "java")); err != nil {
		return "", errors.New("the Java download doesn't contain bin/java")
	}
	// Check it runs before keeping it.
	vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
	out, err := exec.CommandContext(vctx, filepath.Join(root, "bin", "java"), "-version").CombinedOutput()
	vcancel()
	if err != nil {
		return "", fmt.Errorf("the downloaded Java doesn't run on this computer: %v %s", err, strings.TrimSpace(string(out)))
	}
	target := filepath.Join(m.runtimesDir(), "java-"+strconv.Itoa(major))
	_ = os.RemoveAll(target)
	if err := os.Rename(root, target); err != nil {
		return "", err
	}
	_ = os.Chmod(filepath.Join(target, "bin", "java"), 0o755)
	say(fmt.Sprintf("Java %d is installed (%s).", major, assets[0].ReleaseName))
	m.log.Info("java runtime installed", "major", major, "release", assets[0].ReleaseName)
	return filepath.Join(target, "bin", "java"), nil
}

// downloadVerified downloads url into dir and checks its SHA-256 when one is
// given.
func (m *Manager) downloadVerified(ctx context.Context, url, dir, sum string, say func(string), agent string) (string, error) {
	file, err := m.downloadAs(ctx, url, dir, say, agent)
	if err != nil {
		return "", err
	}
	if sum == "" {
		return file, nil
	}
	f, err := os.Open(file)
	if err != nil {
		os.Remove(file)
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err == nil && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sum) {
		err = errors.New("the download is damaged (its checksum doesn't match); try again")
	}
	if err != nil {
		os.Remove(file)
		return "", err
	}
	return file, nil
}

// ---- install and update ----

// installJava downloads Paper (and Java if needed) into the server folder.
func (s *Server) installJava(update bool) error {
	ctx, cancel := context.WithTimeout(s.m.ctx, 30*time.Minute)
	defer cancel()
	s.mu.Lock()
	current, build := s.meta.Version, s.meta.Build
	// Overnight, a held server only gets its console support updated.
	pluginsOnly := update && s.autoUpdating && s.meta.HoldVersion
	s.mu.Unlock()
	_, statErr := os.Stat(filepath.Join(s.dir(), paperJar))
	if pluginsOnly && statErr == nil {
		return s.installConsoles(ctx, true)
	}

	s.say("Asking PaperMC for the current Paper server…")
	r, err := s.m.latestPaper(ctx)
	if err != nil {
		return err
	}
	if update && statErr == nil && !javaNewer(r, current, build) {
		// Java may still be missing (a moved data folder): put it back.
		s.mu.Lock()
		major := s.meta.JavaMajor
		s.mu.Unlock()
		if major == 0 {
			major = s.m.javaMajorFor(ctx, current)
		}
		if _, err := s.m.ensureJava(ctx, major, s.say); err != nil {
			return err
		}
		s.mu.Lock()
		s.meta.JavaMajor = major
		s.mu.Unlock()
		_ = s.saveMeta()
		s.say("Already on the current version (" + r.label() + ").")
		s.mu.Lock()
		auto := s.autoUpdating // overnight, that was for console support
		s.mu.Unlock()
		return s.installConsoles(ctx, auto)
	}
	if update && current != "" && r.Version != current {
		s.say("This moves the server from Minecraft " + current + " to " + r.Version + ". Worlds can't go back to an older version afterwards (the backup can).")
	}
	major := s.m.javaMajorFor(ctx, r.Version)
	if _, err := s.m.ensureJava(ctx, major, s.say); err != nil {
		return err
	}
	s.say("Installing Paper " + r.label() + ". By downloading it you accept the Minecraft EULA: https://www.minecraft.net/eula")
	file, err := s.m.downloadVerified(ctx, r.URL, s.m.serversDir(), r.SHA256, s.say, s.m.javaUserAgent())
	if err != nil {
		return err
	}
	defer os.Remove(file)
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(file, filepath.Join(s.dir(), paperJar)); err != nil {
		return err
	}
	// The EULA was accepted when the server was added.
	if err := os.WriteFile(filepath.Join(s.dir(), "eula.txt"), []byte("# Accepted in the Blockheads panel when the server was added.\neula=true\n"), 0o644); err != nil {
		return err
	}
	s.mu.Lock()
	s.meta.Version, s.meta.Build, s.meta.JavaMajor = r.Version, r.Build, major
	s.mu.Unlock()
	if err := s.saveMeta(); err != nil {
		return err
	}
	s.mu.Lock()
	err = s.applyJavaProperties(!update)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("couldn't set up server.properties: %w", err)
	}
	_ = os.Remove(s.incompleteMarker())
	s.say("Paper " + r.label() + " is installed.")
	return s.installConsoles(ctx, false)
}

// installConsoles installs or updates console support during an install or
// update. If it can't, the server still works for Java players, so that's
// said rather than failing the update, unless console support is all the
// update was for (only, so it's reported as failed).
func (s *Server) installConsoles(ctx context.Context, only bool) error {
	if !s.ConsolesOn() {
		_, err := s.ensureConsolePlugins(ctx) // removes them if they're there
		return err
	}
	updated, err := s.ensureConsolePlugins(ctx)
	if err != nil && only {
		return err
	}
	if err != nil {
		s.say(err.Error() + " Java players can still join; try Update now again later.")
		return nil
	}
	if updated {
		s.mu.Lock()
		s.updatedConsoles = true
		s.mu.Unlock()
	} else {
		s.say("Console support is up to date.")
	}
	return nil
}

// javaProperties are a new Java server's settings: safe for a family server.
var javaProperties = []string{
	"white-list=true",
	"enforce-whitelist=true",
	"online-mode=true",
	"difficulty=easy",
	"spawn-protection=0",
	"enable-query=false",
	"enable-rcon=false",
	"level-name=" + javaWorldDefault,
}

// applyJavaProperties sets what the panel manages. Caller holds s.mu.
func (s *Server) applyJavaProperties(fresh bool) error {
	path := s.propertiesPath()
	p, err := readProperties(path)
	if errors.Is(err, os.ErrNotExist) {
		p, err = &properties{}, nil
		fresh = true
	}
	if err != nil {
		return err
	}
	before := strings.Join(p.lines, "\n")
	if fresh {
		for _, kv := range javaProperties {
			k, v, _ := strings.Cut(kv, "=")
			if _, ok := p.get(k); !ok {
				p.set(k, v)
			}
		}
		p.set("motd", s.meta.Name)
	}
	p.set("server-port", strconv.Itoa(s.meta.Port))
	p.set("query.port", strconv.Itoa(s.meta.Port))
	if s.consolesOnLocked() {
		// Query is UDP on the same port, which Geyser needs for consoles.
		p.set("enable-query", "false")
	}
	if strings.Join(p.lines, "\n") == before {
		return nil
	}
	return p.write(path)
}

// javaCommand returns the command line that starts a Java server.
func (s *Server) javaCommand() (string, []string, error) {
	major := s.meta.JavaMajor
	if major == 0 {
		major = 21
	}
	bin := s.m.javaBinary(major)
	if bin == "" {
		return "", nil, fmt.Errorf("Java %d isn't installed; use Update to install it", major)
	}
	mem := s.meta.MemoryMB
	if mem <= 0 {
		mem = defaultMemoryMB
	}
	args := []string{
		fmt.Sprintf("-Xms%dM", mem/2), fmt.Sprintf("-Xmx%dM", mem),
		"-XX:+UseG1GC", "-XX:+ParallelRefProcEnabled", "-XX:MaxGCPauseMillis=200",
		"-Dfile.encoding=UTF-8",
	}
	if s.consolesLive || fileExists(filepath.Join(s.dir(), "plugins", consolePlugins[0].File)) {
		// Geyser takes console players on the server's own port (UDP), never
		// its default (the console server list's port).
		args = append(args, "-DgeyserUdpPort="+strconv.Itoa(s.meta.Port))
	}
	args = append(args,
		"-jar", paperJar, "--nogui", "--world-container", "worlds")
	return bin, args, nil
}

// SetMemory sets how much memory a Java server may use (in MB), from the next
// start.
func (s *Server) SetMemory(mb int) error {
	if !s.isJava() {
		return errors.New("only Java servers have a memory setting")
	}
	if mb < 512 || mb > 32768 {
		return errors.New("pick between 512 MB and 32 GB")
	}
	s.mu.Lock()
	s.meta.MemoryMB = mb
	s.mu.Unlock()
	return s.saveMeta()
}
