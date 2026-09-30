package web

import (
	"errors"
	"net/http"

	"github.com/ScottSchneck/blockheads-control-panel/internal/servers"
)

var errNoServer = errors.New("no such server")

// Deleting servers (owner only), bringing them back, and overnight upkeep.

func (s *Server) lifecycleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("DELETE /api/servers/{id}", ownerOnly(s.deleteServer))
	mux.HandleFunc("GET /api/deleted-servers", ownerOnly(s.listDeleted))
	mux.HandleFunc("POST /api/deleted-servers/{id}/bring-back", ownerOnly(s.bringBack))
	mux.HandleFunc("DELETE /api/deleted-servers/{id}", ownerOnly(s.forgetDeleted))
	mux.HandleFunc("GET /api/nightly", ownerOnly(s.getNightly))
	mux.HandleFunc("PUT /api/nightly", ownerOnly(s.putNightly))
	mux.HandleFunc("POST /api/servers/{id}/hold-version", s.withServer(levelCare, s.holdVersion))
}

func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	srv, ok := s.mgr.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errNoServer)
		return
	}
	name := srv.Status().Name
	if err := s.mgr.DeleteServer(id); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	s.note(r, nil, "deleted the server "+name+" (its backups are kept)")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listDeleted(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.DeletedServers())
}

func (s *Server) bringBack(w http.ResponseWriter, r *http.Request) {
	st, err := s.mgr.BringBack(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	if srv, ok := s.mgr.Get(st.ID); ok {
		s.note(r, srv, "brought the server back")
	}
	writeJSON(w, http.StatusAccepted, st)
}

func (s *Server) forgetDeleted(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mgr.ForgetDeleted(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Its name can now go to a new server: nobody keeps a role on it.
	for _, u := range s.auth.Users() {
		if _, ok := u.Grants[id]; ok {
			if err := s.auth.SetUser(u.Username, nil, map[string]string{id: ""}); err != nil {
				s.log.Warn("couldn't remove a role on a deleted server", "user", u.Username, "error", err)
			}
		}
	}
	s.note(r, nil, "removed the backups of the deleted server "+id)
	writeJSON(w, http.StatusOK, s.mgr.DeletedServers())
}

func (s *Server) getNightly(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.NightlyPlan())
}

func (s *Server) putNightly(w http.ResponseWriter, r *http.Request) {
	var req servers.Nightly
	if !readBody(w, r, &req) {
		return
	}
	if err := s.mgr.SetNightlyPlan(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.note(r, nil, "changed the overnight updates and restarts")
	writeJSON(w, http.StatusOK, s.mgr.NightlyPlan())
}

func (s *Server) holdVersion(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	var req struct {
		Hold bool `json:"hold"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if err := srv.SetHoldVersion(req.Hold); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if req.Hold {
		s.note(r, srv, "kept the server on its Bedrock version")
	} else {
		s.note(r, srv, "let the server update overnight")
	}
	writeJSON(w, http.StatusOK, srv.Status())
}
