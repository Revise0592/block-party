package servers

import (
	"github.com/ScottSchneck/block-party/internal/notify"
)

// Notifications about servers (see the notify package). Options.Notify may
// be nil.

func (m *Manager) notify(e notify.Event) {
	if m.opts.Notify != nil {
		m.opts.Notify(e)
	}
}

// notifyLocked sends an event about the server. Caller holds s.mu; sending
// only queues, so it doesn't block.
func (s *Server) notifyLocked(kind, title, text, key string) {
	s.m.notify(notify.Event{Kind: kind, Server: s.meta.Name, Title: title, Text: text, Key: key})
}

func (s *Server) notify(kind, title, text, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyLocked(kind, title, text, key)
}

// announceRelease tells the owner about a new Bedrock version once, when
// overnight updates won't take care of it and a server is behind.
func (m *Manager) announceRelease(version string) {
	if version == "" || m.NightlyPlan().AutoUpdate || m.Settings().AnnouncedVersion == version {
		return
	}
	var behind []string
	for _, s := range m.all() {
		st := s.Status()
		if st.Version != "" && !st.Preview && versionNewer(version, st.Version) {
			behind = append(behind, st.Name)
		}
	}
	_ = m.changeSettings(func(s *Settings) { s.AnnouncedVersion = version })
	if len(behind) == 0 {
		return
	}
	text := "Press Update on each server in the panel, or turn on overnight updates (Help, Overnight updates and restarts)."
	if len(behind) == 1 {
		text = behind[0] + " can update. " + text
	} else {
		text = joinNames(behind) + " can update. " + text
	}
	m.notify(notify.Event{Kind: notify.NewVersion, Title: "Bedrock " + version + " is out", Text: text, Key: "version/" + version})
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	out := ""
	for i, n := range names {
		switch {
		case i == 0:
			out = n
		case i == len(names)-1:
			out += " and " + n
		default:
			out += ", " + n
		}
	}
	return out
}
