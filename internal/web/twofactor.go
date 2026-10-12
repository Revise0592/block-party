package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/skip2/go-qrcode"
)

// Two-factor sign-in: a code from an authenticator app after the password.

func (s *Server) sessionToken(r *http.Request) string {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		return c.Value
	}
	return ""
}

func (s *Server) authLoginCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !readBody(w, r, &req) {
		return
	}
	token, err := s.auth.LoginCode(r.Context(), clientIP(r), req.Challenge, req.Code)
	if err != nil {
		s.log.Warn("sign-in code failed", "from", clientIP(r), "error", err)
		authError(w, err)
		return
	}
	name := s.auth.Check(token)
	s.log.Info("signed in with two-factor", "username", name, "from", clientIP(r))
	s.setSession(w, token)
	writeJSON(w, http.StatusOK, map[string]string{"username": name})
}

func (s *Server) twoView(name string) map[string]any {
	on, left := s.auth.TwoFactorStatus(name)
	return map[string]any{"on": on, "recoveryLeft": left}
}

func (s *Server) twoStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.twoView(me(r).Name))
}

// qrSVG draws a QR code as SVG (shown as an image; the page allows data:
// images).
func qrSVG(text string) (string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return "", err
	}
	q.DisableBorder = false
	bits := q.Bitmap()
	n := len(bits)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y, row := range bits {
		for x, on := range row {
			if on {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

func (s *Server) twoStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !readBody(w, r, &req) {
		return
	}
	secret, link, err := s.auth.StartTwoFactor(r.Context(), clientIP(r), s.sessionToken(r), req.Password, "Blockheads")
	if err != nil {
		authError(w, err)
		return
	}
	svg, err := qrSVG(link)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// The secret is grouped in fours for typing by hand.
	var groups []string
	for i := 0; i < len(secret); i += 4 {
		groups = append(groups, secret[i:min(i+4, len(secret))])
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": strings.Join(groups, " "), "link": link, "qr": svg})
}

func (s *Server) twoConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !readBody(w, r, &req) {
		return
	}
	codes, err := s.auth.ConfirmTwoFactor(clientIP(r), s.sessionToken(r), req.Code)
	if err != nil {
		authError(w, err)
		return
	}
	s.note(r, nil, "turned on two-factor sign-in")
	s.log.Info("two-factor sign-in turned on", "username", me(r).Name)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "status": s.twoView(me(r).Name)})
}

func (s *Server) twoDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if err := s.auth.DisableTwoFactor(r.Context(), clientIP(r), s.sessionToken(r), req.Password); err != nil {
		authError(w, err)
		return
	}
	s.note(r, nil, "turned off two-factor sign-in")
	s.log.Info("two-factor sign-in turned off", "username", me(r).Name)
	writeJSON(w, http.StatusOK, s.twoView(me(r).Name))
}

func (s *Server) twoRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !readBody(w, r, &req) {
		return
	}
	codes, err := s.auth.NewRecoveryCodes(r.Context(), clientIP(r), s.sessionToken(r), req.Password)
	if err != nil {
		authError(w, err)
		return
	}
	s.note(r, nil, "made new two-factor recovery codes")
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "status": s.twoView(me(r).Name)})
}

func (s *Server) twoResetUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.auth.ResetUserTwoFactor(name); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.note(r, nil, "turned off two-factor sign-in for "+name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
