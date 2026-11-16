package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// fakeKV is a small KV v2 server: versions, check-and-set, tokens, AppRole.
type fakeKV struct {
	mu        sync.Mutex
	mount     string
	docs      map[string][]map[string]any // path under data/ -> versions
	tokens    map[string]bool
	staticTok string
	roleID    string
	secretID  string
	lease     int
	logins    int
	paths     []string // every request path seen (decoded)
	caps      []string // what capabilities-self answers
	denyData  bool     // answer 403 on data paths whatever the token
	srv       *httptest.Server
}

func newFakeKV(mount string) *fakeKV {
	f := &fakeKV{
		mount:  mount,
		docs:   map[string][]map[string]any{},
		tokens: map[string]bool{},
		caps:   []string{"create", "read", "update"},
	}
	f.srv = httptest.NewServer(f)
	return f
}

func (f *fakeKV) Close() { f.srv.Close() }

func (f *fakeKV) addToken(t string) {
	f.mu.Lock()
	f.tokens[t] = true
	f.mu.Unlock()
}

func (f *fakeKV) revokeAll() {
	f.mu.Lock()
	f.tokens = map[string]bool{}
	f.mu.Unlock()
}

func (f *fakeKV) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *fakeKV) version(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.docs[path])
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path)
	body, _ := io.ReadAll(r.Body)

	if r.URL.Path == "/v1/auth/approle/login" {
		var in struct{ RoleID, SecretID string }
		var raw map[string]string
		json.Unmarshal(body, &raw)
		in.RoleID, in.SecretID = raw["role_id"], raw["secret_id"]
		if in.RoleID != f.roleID || in.SecretID != f.secretID || f.roleID == "" {
			reply(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		f.logins++
		tok := fmt.Sprintf("s.login%d", f.logins)
		f.tokens[tok] = true
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.lease}})
		return
	}

	tok := r.Header.Get("X-Vault-Token")
	if tok == "" || !(f.tokens[tok] || tok == f.staticTok) {
		reply(w, 403, map[string]any{"errors": []string{"permission denied"}})
		return
	}

	if r.URL.Path == "/v1/sys/capabilities-self" && r.Method == "POST" {
		var in struct {
			Paths []string `json:"paths"`
		}
		json.Unmarshal(body, &in)
		out := map[string]any{"capabilities": f.caps}
		for _, p := range in.Paths {
			out[p] = f.caps
		}
		reply(w, 200, out)
		return
	}

	if f.denyData && strings.Contains(r.URL.Path, "/data/") {
		reply(w, 403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	prefix := "/v1/" + f.mount + "/data/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		reply(w, 404, map[string]any{"errors": []string{"unsupported path"}})
		return
	}
	p := strings.TrimPrefix(r.URL.Path, prefix)
	switch r.Method {
	case "GET":
		vs := f.docs[p]
		if len(vs) == 0 {
			reply(w, 404, map[string]any{"errors": []string{}})
			return
		}
		reply(w, 200, map[string]any{"data": map[string]any{
			"data":     vs[len(vs)-1],
			"metadata": map[string]any{"version": len(vs)},
		}})
	case "POST", "PUT":
		var in struct {
			Options struct {
				CAS *int `json:"cas"`
			} `json:"options"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(body, &in); err != nil || in.Data == nil {
			reply(w, 400, map[string]any{"errors": []string{"no data provided"}})
			return
		}
		if in.Options.CAS != nil && *in.Options.CAS != len(f.docs[p]) {
			reply(w, 400, map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
			return
		}
		f.docs[p] = append(f.docs[p], in.Data)
		reply(w, 200, map[string]any{"data": map[string]any{"version": len(f.docs[p])}})
	default:
		reply(w, 405, nil)
	}
}
