package servers

import (
	"sync"
	"testing"
	"time"

	"github.com/ScottSchneck/block-party/internal/notify"
)

func TestServerEventsAreSent(t *testing.T) {
	mojang := newFakeMojang(t, "1.0.0.1")
	var mu sync.Mutex
	var got []notify.Event
	m := New(Options{DataDir: t.TempDir(), DownloadAPI: mojang.srv.URL + "/links", StopTimeout: time.Second,
		Notify: func(e notify.Event) { mu.Lock(); got = append(got, e); mu.Unlock() }})
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.StopAll)
	s := createRunning(t, m, "Family")
	kinds := func() map[string]notify.Event {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]notify.Event{}
		for _, e := range got {
			out[e.Kind] = e
		}
		return out
	}
	s.Command("join Steve")
	waitConsole(t, s, "Player connected")
	m.NoteMenuPick(s.Status().Port, "Stranger", "", true)
	waitConsole(t, s, "Stranger tried to join")
	s.Command("crash")
	waitConsole(t, s, "stopped unexpectedly")
	k := kinds()
	if e := k[notify.PlayerJoined]; e.Title != "Steve is playing on Family" {
		t.Errorf("joined: %+v", e)
	}
	if e := k[notify.JoinAttempt]; e.Server != "Family" || e.Key == "" {
		t.Errorf("attempt: %+v", e)
	}
	if e := k[notify.Crash]; e.Title != "Family crashed" {
		t.Errorf("crash: %+v", e)
	}
	// A new release is announced once, when overnight updates are off.
	waitFor(t, s, "running again", state(StateRunning))
	m.announceRelease("1.0.0.2")
	m.announceRelease("1.0.0.2")
	n := 0
	mu.Lock()
	for _, e := range got {
		if e.Kind == notify.NewVersion {
			n++
		}
	}
	mu.Unlock()
	if n != 1 {
		t.Errorf("announced %d times", n)
	}
}
