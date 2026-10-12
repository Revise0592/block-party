package web

import (
	"context"
	"net/http"
	"time"

	"github.com/ScottSchneck/block-party/internal/notify"
)

// Notifications (owner only). Passwords and tokens are never sent back to
// the page; it sends them only when they change.

func (s *Server) notifyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/notifications", ownerOnly(s.getNotify))
	mux.HandleFunc("PUT /api/notifications", ownerOnly(s.putNotify))
	mux.HandleFunc("POST /api/notifications/test/{channel}", ownerOnly(s.testNotify))
}

func (s *Server) getNotify(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.notifier.View())
}

func (s *Server) putNotify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Settings notify.Settings `json:"settings"`
		Clear    map[string]bool `json:"clear"`
	}
	if !readBodyLimit(w, r, &req, 64<<10) {
		return
	}
	v, err := s.notifier.Update(req.Settings, req.Clear)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.note(r, nil, "changed the notification settings")
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err := s.notifier.Test(ctx, r.PathValue("channel")); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
