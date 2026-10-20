package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ScottSchneck/block-party/internal/outside"
	"github.com/ScottSchneck/block-party/internal/playit"
	"github.com/ScottSchneck/block-party/internal/servers"
)

// Friends outside the house. The owner sets it up (the address friends use,
// the router, consoles); anyone who takes care of a server can open it to
// them or close it.

func (s *Server) outsideRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/outside", ownerOnly(s.getOutside))
	mux.HandleFunc("PUT /api/outside", ownerOnly(s.putOutside))
	mux.HandleFunc("POST /api/outside/check", ownerOnly(s.checkOutside))
	mux.HandleFunc("POST /api/outside/playit/claim", ownerOnly(s.startPlayitClaim))
	mux.HandleFunc("POST /api/outside/playit/claim/check", ownerOnly(s.checkPlayitClaim))
	mux.HandleFunc("DELETE /api/outside/playit", ownerOnly(s.unlinkPlayit))
	mux.HandleFunc("GET /api/servers/{id}/outside", s.withServer(levelRun, s.serverOutside))
	mux.HandleFunc("POST /api/servers/{id}/outside", s.withServer(levelCare, s.setServerOutside))
}

// OutsideServers lists the panel's servers for the outside package.
func OutsideServers(mgr *servers.Manager) func() []outside.Server {
	return func() []outside.Server {
		var list []outside.Server
		for _, st := range mgr.List() {
			srv, ok := mgr.Get(st.ID)
			if !ok {
				continue
			}
			s := outsideServer(st)
			if st.Outside {
				s.Problem = srv.OutsideProblem()
			}
			list = append(list, s)
		}
		return list
	}
}

// outsideServer is a server as the outside package sees it: which ports it
// needs forwarded.
func outsideServer(st servers.Status) outside.Server {
	s := outside.Server{ID: st.ID, Name: st.Name, Port: st.Port, Open: st.Outside}
	switch st.Type {
	case servers.TypeJava:
		s.Java, s.JavaConsoles = true, st.Consoles
		if st.Consoles {
			s.NetherNetPort = servers.GeyserNetherNetPort(st.Port)
		}
	case servers.TypeHytale:
	default:
		first, last := servers.BedrockUDPPorts(st.Port)
		s.Bedrock, s.UDPPorts = true, [2]int{first, last}
	}
	return s
}

// forwardsText describes forwards for people, ranges joined up:
// "TCP 19136", "UDP 49152-49171".
func forwardsText(ports []outside.Port) []string {
	var out []string
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1].Proto == ports[i].Proto && ports[j+1].Port == ports[j].Port+1 {
			j++
		}
		if j > i {
			out = append(out, fmt.Sprintf("%s %d-%d", ports[i].Proto, ports[i].Port, ports[j].Port))
		} else {
			out = append(out, fmt.Sprintf("%s %d", ports[i].Proto, ports[i].Port))
		}
		i = j + 1
	}
	return out
}

// refresh works outside access out again, waiting a little for the answer.
func (s *Server) refreshOutside(r *http.Request) outside.Status {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	return s.out.Refresh(ctx)
}

func (s *Server) getOutside(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.out.Status())
}

func (s *Server) putOutside(w http.ResponseWriter, r *http.Request) {
	var req outside.Settings
	if !readBody(w, r, &req) {
		return
	}
	before := s.out.Settings()
	if err := s.out.SetSettings(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	switch {
	case req.Enabled && !before.Enabled:
		s.note(r, nil, "turned on outside access for friends")
	case !req.Enabled && before.Enabled:
		s.note(r, nil, "turned off outside access for friends")
	default:
		s.note(r, nil, "changed the outside access settings")
	}
	writeJSON(w, http.StatusOK, s.refreshOutside(r))
}

func (s *Server) checkOutside(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.refreshOutside(r))
}

// Linking playit.gg: the owner approves the panel on playit.gg (the page
// opens in a new tab) while the panel asks whether they have.

func (s *Server) startPlayitClaim(w http.ResponseWriter, r *http.Request) {
	url, err := s.out.Playit().StartClaim(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

func (s *Server) checkPlayitClaim(w http.ResponseWriter, r *http.Request) {
	state, err := s.out.Playit().CheckClaim(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if state == playit.ClaimLinked {
		s.note(r, nil, "linked a playit.gg account")
		writeJSON(w, http.StatusOK, map[string]any{"state": state, "outside": s.refreshOutside(r)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": state})
}

func (s *Server) unlinkPlayit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.out.Playit().Unlink(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.note(r, nil, "unlinked playit.gg")
	writeJSON(w, http.StatusOK, s.refreshOutside(r))
}

// serverOutsideView is what a server's page shows about friends outside.
type serverOutsideView struct {
	Open     bool   `json:"open"`    // marked open
	Reached  bool   `json:"reached"` // and nothing stops it
	Problem  string `json:"problem,omitempty"`
	Enabled  bool   `json:"enabled"` // outside access is on in the panel
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port"`
	Consoles bool   `json:"consoles"`
	// ConsoleDNS is the address friends' consoles use as their DNS.
	ConsoleDNS string `json:"consoleDNS,omitempty"`
	UPnP       bool   `json:"upnp"`
	Opened     bool   `json:"opened"` // the router opened the port
	PortError  string `json:"portError,omitempty"`
	Shared     bool   `json:"shared"`
	Owner      string `json:"owner"`
	Java       bool   `json:"java"`
	// JavaConsoles: a Java server consoles can join too (same port, UDP).
	JavaConsoles bool `json:"javaConsoles,omitempty"`
	Hytale       bool `json:"hytale,omitempty"`
	// BedrockPort is the port Bedrock players type (a Java server's takes
	// NetherNet, which Minecraft 26.60 and later use, on the next port up).
	BedrockPort int `json:"bedrockPort,omitempty"`
	// Forwards are the forwards it needs, for setting up by hand.
	Forwards []string `json:"forwards,omitempty"`
	// Playit: friends come in through playit.gg. Address and Port are then
	// the server's playit.gg address, for Java players only.
	Playit bool `json:"playit,omitempty"`
	// PlayitCant: through playit.gg friends can't reach this server at all
	// (it isn't a Java server).
	PlayitCant bool `json:"playitCant,omitempty"`
}

func (s *Server) outsideView(srv *servers.Server, st outside.Status) serverOutsideView {
	ss := srv.Status()
	v := serverOutsideView{
		Open: ss.Outside, Enabled: st.Settings.Enabled, Address: st.Address, Port: ss.Port,
		Consoles: st.Settings.Consoles, UPnP: st.Settings.UPnP, Shared: st.Shared, Owner: s.auth.Username(),
		Java: ss.Type == servers.TypeJava,
	}
	v.JavaConsoles = v.Java && ss.Consoles
	v.Hytale = ss.Type == servers.TypeHytale
	need := outsideServer(ss).Forwards()
	v.Forwards = forwardsText(need)
	v.BedrockPort = ss.Port
	if v.JavaConsoles {
		v.BedrockPort = servers.GeyserNetherNetPort(ss.Port)
	}
	// The address consoles outside use as their DNS: where the address
	// friends use leads (it's never a home address; see outside).
	v.ConsoleDNS = st.PublicIP
	if st.AddressIP != "" {
		v.ConsoleDNS = st.AddressIP
	}
	if ss.Outside {
		v.Problem = srv.OutsideProblem()
	}
	for _, x := range st.Servers {
		if x.ID == ss.ID {
			v.Reached = x.Reached && v.Problem == ""
		}
	}
	// Opened only when every forward it needs is.
	opened := 0
	for _, p := range st.Ports {
		if !slices.ContainsFunc(need, func(n outside.Port) bool { return n.Port == p.Port.Port && n.Proto == p.Proto }) {
			continue
		}
		if p.Opened {
			opened++
		}
		if v.PortError == "" {
			v.PortError = p.Error
		}
	}
	v.Opened = opened == len(need)
	if st.Settings.Playit {
		s.playitView(&v, ss.ID)
	}
	return v
}

// playitView fills in a server's playit.gg address. Only Java servers
// have one, for Java players: Bedrock players and consoles (through Geyser
// too) join over NetherNet from Minecraft 26.60, which playit.gg's free
// plan can't carry.
func (s *Server) playitView(v *serverOutsideView, id string) {
	v.Playit, v.UPnP, v.Shared, v.Consoles, v.ConsoleDNS = true, false, false, false, ""
	v.Address, v.Port, v.BedrockPort, v.Forwards, v.Opened, v.PortError = "", 0, 0, nil, false, ""
	if !v.Java {
		v.PlayitCant, v.Reached = true, false
		return
	}
	t, ok := s.out.Playit().Tunnel(id, "tcp")
	if ok {
		v.Address, v.Port, v.Opened, v.PortError = t.Address, t.PublicPort, t.Ready, t.Problem
	}
	if !s.out.Playit().Linked() {
		v.Opened, v.PortError = false, "playit.gg isn't linked yet"
	}
}

func (s *Server) serverOutside(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	writeJSON(w, http.StatusOK, s.outsideView(srv, s.out.Status()))
}

func (s *Server) setServerOutside(w http.ResponseWriter, r *http.Request, srv *servers.Server) {
	var req struct {
		Open bool `json:"open"`
	}
	if !readBody(w, r, &req) {
		return
	}
	was := srv.Outside()
	if err := srv.SetOutside(req.Open); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	if was != req.Open {
		if req.Open {
			s.note(r, srv, "opened the server to friends outside the house")
		} else {
			s.note(r, srv, "closed the server to friends outside the house")
		}
	}
	writeJSON(w, http.StatusOK, s.outsideView(srv, s.refreshOutside(r)))
}
