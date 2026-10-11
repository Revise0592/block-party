package web

import (
	"net/http"
)

// The Hytale account (owner only): signing in, so the panel can download
// Hytale servers and sign them in to Hytale.

func (s *Server) hytaleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/hytale/account", s.hytaleAccount)
	mux.HandleFunc("POST /api/hytale/signin", ownerOnly(s.hytaleSignIn))
	mux.HandleFunc("POST /api/hytale/signin/cancel", ownerOnly(s.hytaleCancel))
	mux.HandleFunc("DELETE /api/hytale/account", ownerOnly(s.hytaleSignOut))
}

// hytaleAccount tells anyone who can add servers whether Hytale servers can
// be added; the owner also sees a sign-in in progress.
func (s *Server) hytaleAccount(w http.ResponseWriter, r *http.Request) {
	p := me(r)
	v := s.mgr.HytaleAccount()
	if !p.Owner {
		v.Pending, v.Error = nil, ""
		if !p.CanAdd {
			v.Username = ""
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) hytaleSignIn(w http.ResponseWriter, r *http.Request) {
	v, err := s.mgr.StartHytaleSignIn()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	s.note(r, nil, "started signing in to Hytale")
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) hytaleCancel(w http.ResponseWriter, r *http.Request) {
	s.mgr.CancelHytaleSignIn()
	writeJSON(w, http.StatusOK, s.mgr.HytaleAccount())
}

func (s *Server) hytaleSignOut(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.SignOutHytale(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.note(r, nil, "signed the panel out of Hytale")
	writeJSON(w, http.StatusOK, s.mgr.HytaleAccount())
}
