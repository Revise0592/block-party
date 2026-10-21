package web

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ScottSchneck/block-party/internal/servers"
)

func (s *Server) settingsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/servers/{id}/settings", s.withServer(levelRun, s.getServerSettings))
	mux.HandleFunc("POST /api/servers/{id}/settings", s.withServer(levelRun, s.saveServerSettings))
	mux.HandleFunc("GET /api/servers/{id}/properties", s.withServer(levelRun, s.getProperties))
	mux.HandleFunc("PUT /api/servers/{id}/properties", s.withServer(levelRun, s.putProperties))
	mux.HandleFunc("POST /api/servers/{id}/rename", s.withServer(levelRun, s.renameServer))
	mux.HandleFunc("GET /api/servers/{id}/icon", s.withServer(levelSee, s.getIcon))
	mux.HandleFunc("PUT /api/servers/{id}/icon", s.withServer(levelRun, s.putIcon))
	mux.HandleFunc("DELETE /api/servers/{id}/icon", s.withServer(levelRun, s.deleteIcon))
}

func (s *Server) getServerSettings(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	v, err := srv.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) saveServerSettings(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	var req struct {
		Values map[string]string `json:"values"`
	}
	if !readBody(w, r, &req) {
		return
	}
	changes, err := srv.SaveSettings(req.Values)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(changes) > 0 {
		var what []string
		for _, c := range changes {
			what = append(what, c.Label)
		}
		s.note(r, srv, "changed settings: "+strings.Join(what, ", "))
	}
	v, err := srv.Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if changes == nil {
		changes = []servers.SettingsChange{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": changes, "settings": v})
}

func (s *Server) getProperties(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	text, err := srv.RawProperties()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text})
}

func (s *Server) putProperties(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	var req struct {
		Text string `json:"text"`
	}
	// The editor sends the whole file (JSON-escaped), so allow more than usual.
	if !readBodyLimit(w, r, &req, 1<<20) {
		return
	}
	if err := s.did(r, srv, srv.SaveRawProperties(req.Text), "edited server.properties"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.getProperties(w, r, srv)
}

func (s *Server) renameServer(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	var req struct {
		Name string `json:"name"`
	}
	if !readBody(w, r, &req) {
		return
	}
	old := srv.Status().Name
	if err := s.did(r, srv, srv.Rename(req.Name), "renamed the server from "+strconv.Quote(old)); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, srv.Status())
}

func (s *Server) getIcon(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	b, err := srv.Icon()
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, errors.New("this server has no picture"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// The page asks for it with the time it changed, so a copy can be kept.
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(b)
}

func (s *Server) putIcon(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, servers.MaxIconUpload))
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("that picture is bigger than 15 MB; try a smaller one"))
		return
	}
	if err := s.did(r, srv, srv.SetIcon(b), "changed the server picture"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, srv.Status())
}

func (s *Server) deleteIcon(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	if err := s.did(r, srv, srv.RemoveIcon(), "removed the server picture"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, srv.Status())
}
