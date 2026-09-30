package servers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeleteAndBringBack(t *testing.T) {
	mojang := newFakeMojang(t, "1.0.0.1")
	m := newTestManager(t, mojang, time.Second)
	s := createRunning(t, m, "Ava's Server")
	id, port := s.ID(), s.Status().Port
	os.MkdirAll(filepath.Join(s.dir(), "worlds", "Bedrock level", "db"), 0o755)
	os.WriteFile(filepath.Join(s.dir(), "worlds", "Bedrock level", "level.dat"), []byte("ava's world"), 0o644)
	s.SetOutside(true)

	if err := m.DeleteServer(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get(id); ok {
		t.Fatal("still listed")
	}
	if _, err := os.Stat(s.dir()); err == nil {
		t.Error("folder left")
	}
	if err := s.Start(); err == nil {
		t.Error("a deleted server started")
	}
	// A change still on its way is refused and doesn't bring the folder back.
	up := filepath.Join(t.TempDir(), "w.mcworld")
	writeZip(t, up, map[string]string{"level.dat": "x"})
	if _, err := s.AddWorld(context.Background(), up, "w.mcworld", false); err == nil {
		t.Error("world added to a deleted server")
	}
	if _, err := os.Stat(s.dir()); err == nil {
		t.Error("folder came back")
	}
	del := m.DeletedServers()
	if len(del) != 1 || del[0].ID != id || del[0].Name != "Ava's Server" || !del[0].CanBring || del[0].Backups < 1 {
		t.Fatalf("deleted: %+v", del)
	}
	// Its name isn't given to a new server, so backups never mix.
	if nid := m.newID("Ava's Server"); nid == id {
		t.Error("name reused")
	}
	// A restart of the panel still knows about it.
	m2 := New(Options{DataDir: m.opts.DataDir, DownloadAPI: mojang.srv.URL + "/links"})
	m2.Load()
	if len(m2.DeletedServers()) != 1 {
		t.Error("forgotten after a restart")
	}

	st, err := m.BringBack(id)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != id || st.Port != port {
		t.Errorf("back as %+v", st)
	}
	back, _ := m.Get(id)
	waitFor(t, back, "installed", state(StateStopped))
	if readFile(t, filepath.Join(back.dir(), "worlds", "Bedrock level", "level.dat")) != "ava's world" {
		t.Error("world not back")
	}
	if back.Outside() || back.Status().AutoStart {
		t.Error("came back open or starting on its own")
	}
	if len(m.DeletedServers()) != 0 {
		t.Error("still listed as deleted")
	}
	if err := back.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, back, "running", state(StateRunning))

	// Forgetting a deleted server removes its backups.
	if err := m.DeleteServer(id); err != nil {
		t.Fatal(err)
	}
	if err := m.ForgetDeleted(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.backupsDir(id)); err == nil || len(m.DeletedServers()) != 0 {
		t.Error("backups kept")
	}
}

func TestNightly(t *testing.T) {
	mojang := newFakeMojang(t, "1.0.0.1")
	m := newTestManager(t, mojang, time.Second)
	s := createRunning(t, m, "Family")
	if err := m.SetNightlyPlan(Nightly{AutoUpdate: true, DailyRestart: true, At: "25:00"}); err == nil {
		t.Error("odd time accepted")
	}
	plan := Nightly{AutoUpdate: true, DailyRestart: true, At: "23:30"}
	if err := m.SetNightlyPlan(plan); err != nil {
		t.Fatal(err)
	}
	if got := m.NightlyPlan(); got != plan {
		t.Errorf("plan %+v", got)
	}
	loc := time.Local
	in := time.Date(2026, 10, 1, 1, 0, 0, 0, loc) // 1:30 into the window from 23:30
	out := time.Date(2026, 10, 1, 3, 0, 0, 0, loc)

	// Nothing outside the window, or while someone plays.
	s.nightly(out, plan, "1.0.0.2")
	s.Command("join Steve")
	waitConsole(t, s, "Player connected")
	s.nightly(in, plan, "1.0.0.2")
	if s.Status().State != StateRunning {
		t.Fatal("acted while someone played")
	}
	s.Command("leave Steve")
	waitConsole(t, s, "Player disconnected")
	time.Sleep(100 * time.Millisecond)

	// Held: no update; restart only after an hour up.
	s.SetHoldVersion(true)
	s.nightly(in, plan, "1.0.0.2")
	if s.Status().State != StateRunning || consoleHas(s, "Restarting overnight") {
		b, _, stop := s.Subscribe()
		stop()
		t.Errorf("restarted a server that just started: %v\n%s", s.Status().State, strings.Join(b, "\n"))
	}
	s.mu.Lock()
	s.startedAt = time.Now().Add(-2 * time.Hour)
	s.mu.Unlock()
	s.nightly(in, plan, "1.0.0.2")
	waitConsole(t, s, "Restarting overnight")
	waitFor(t, s, "running again", state(StateRunning))
	// Once a night.
	s.mu.Lock()
	s.startedAt = time.Now().Add(-2 * time.Hour)
	s.mu.Unlock()
	s.SetHoldVersion(false)
	s.nightly(in.Add(time.Minute), plan, "1.0.0.2")
	if consoleHas(s, "Updating to Bedrock") {
		t.Error("acted twice in a night")
	}
	// The next night: an update.
	mojang.release(t, "1.0.0.2")
	s.nightly(in.AddDate(0, 0, 1), plan, "1.0.0.2")
	waitConsole(t, s, "Updating to Bedrock 1.0.0.2 overnight")
	waitFor(t, s, "updated and running", func(st Status) bool { return st.State == StateRunning && st.Version == "1.0.0.2" })
	if !versionNewer("1.26.10.4", "1.26.9.9") || versionNewer("1.26.9", "1.26.9.0") || versionNewer("1.2", "1.10") {
		t.Error("versionNewer")
	}
}
