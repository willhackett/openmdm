// Package profiles turns profile templates into per-device configuration
// profiles, signs them, builds the enrolment profile, and loads profiles from
// a directory.
package profiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/google/uuid"
	"howett.net/plist"

	"openmdm/internal/core"
)

var _ core.Renderer = (*Renderer)(nil)

// uuidNamespace makes the version 5 UUIDs of this program differ from anyone
// else's. It is fixed forever: changing it would change every profile UUID.
var uuidNamespace = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("openmdm.profiles"))

var idPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// Names of the template functions that read secrets.
const (
	fnSecret     = "secret"
	fnSecretData = "secretData"
	fnGlobal     = "globalSecret"
	fnGlobalData = "globalSecretData"
	fnUUID       = "uuid"
)

// Renderer implements core.Renderer.
type Renderer struct {
	secrets      core.SecretStore
	authority    core.Authority
	organization string
}

// NewRenderer makes a Renderer. organization is what {{ .Organization }}
// prints.
func NewRenderer(secrets core.SecretStore, authority core.Authority, organization string) *Renderer {
	return &Renderer{secrets: secrets, authority: authority, organization: organization}
}

// esc XML-escapes s. Everything a template can print passes through it
// before the template sees it, so a template cannot forget to.
func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// userView and deviceView are what the template sees: strings that are
// already escaped.
type userView struct {
	Username, Email, Name string
}

type deviceView struct {
	ID, SerialNumber, DeviceName, Model, OSVersion, Platform string
}

// tplData is the template's dot. User is a method rather than a field so
// that using it on a device with no owner can be noticed.
type tplData struct {
	st           *state
	Organization string
	Device       deviceView
	user         *userView
}

func (t *tplData) User() *userView {
	if t.st.noOwner() {
		return &userView{}
	}
	return t.user
}

// state is one Render (or Validate) call.
type state struct {
	r           *Renderer
	ctx         context.Context
	p           core.Profile
	d           core.Device
	u           *core.User
	placeholder bool

	missing []string
	seen    map[string]bool

	userDoc, globalDoc map[string]string
	userLoaded         bool
	globalLoaded       bool
	fatal              error
}

func (s *state) addMissing(what string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if !s.seen[what] {
		s.seen[what] = true
		s.missing = append(s.missing, what)
	}
}

// noOwner records that the template used .User on an ownerless device.
func (s *state) noOwner() bool {
	if s.u == nil && !s.placeholder {
		s.addMissing("an owner")
		return true
	}
	return false
}

// lookup returns the raw value of a secret. ok is false if it is missing
// (already recorded) or the lookup failed (recorded in s.fatal).
func (s *state) lookup(global bool, name string) (string, bool) {
	if s.fatal != nil {
		return "", false
	}
	if s.placeholder {
		return "placeholder", true
	}
	if !global && s.u == nil {
		s.addMissing("an owner")
		return "", false
	}
	var doc map[string]string
	var err error
	if global {
		if !s.globalLoaded {
			s.globalDoc, err = s.r.secrets.GlobalSecrets(s.ctx)
			s.globalLoaded = true
		}
		doc = s.globalDoc
	} else {
		if !s.userLoaded {
			s.userDoc, err = s.r.secrets.UserSecrets(s.ctx, s.u.Username)
			s.userLoaded = true
		}
		doc = s.userDoc
	}
	if err != nil {
		// The store's error is passed on; it never holds a value.
		s.fatal = fmt.Errorf("reading secrets: %w", err)
		return "", false
	}
	v, found := doc[name]
	if !found || v == "" {
		if global {
			s.addMissing(fmt.Sprintf("global secret %q", name))
		} else {
			s.addMissing(fmt.Sprintf("secret %q", name))
		}
		return "", false
	}
	return v, true
}

func (s *state) funcs() template.FuncMap {
	text := func(global bool) func(string) (string, error) {
		return func(name string) (string, error) {
			v, ok := s.lookup(global, name)
			if s.fatal != nil {
				return "", s.fatal
			}
			if !ok {
				return "", nil
			}
			return esc(v), nil
		}
	}
	data := func(global bool) func(string) (string, error) {
		return func(name string) (string, error) {
			v, ok := s.lookup(global, name)
			if s.fatal != nil {
				return "", s.fatal
			}
			if !ok {
				return "", nil
			}
			if s.placeholder {
				return base64.StdEncoding.EncodeToString([]byte("placeholder")), nil
			}
			// Printed unescaped, so it must be nothing but base64.
			clean := strings.Join(strings.Fields(v), "")
			if _, err := base64.StdEncoding.DecodeString(clean); err != nil {
				kind := "secret"
				if global {
					kind = "global secret"
				}
				return "", fmt.Errorf("%s %q is not valid base64", kind, name)
			}
			return clean, nil
		}
	}
	return template.FuncMap{
		fnSecret:     text(false),
		fnSecretData: data(false),
		fnGlobal:     text(true),
		fnGlobalData: data(true),
		fnUUID: func(label string) string {
			return strings.ToUpper(uuid.NewSHA1(uuidNamespace,
				[]byte(s.p.ID+"\x00"+s.d.ID+"\x00"+label)).String())
		},
	}
}

func stubFuncs() template.FuncMap {
	f := func(string) string { return "" }
	return template.FuncMap{fnSecret: f, fnSecretData: f, fnGlobal: f, fnGlobalData: f, fnUUID: f}
}

func parseTemplate(src string, funcs template.FuncMap) (*template.Template, error) {
	t, err := template.New("profile").Option("missingkey=error").Funcs(funcs).Parse(src)
	if err != nil {
		return nil, fmt.Errorf("%w: template does not parse: %v", core.ErrInvalid, err)
	}
	return t, nil
}

func (s *state) execute() ([]byte, error) {
	t, err := parseTemplate(s.p.Template, s.funcs())
	if err != nil {
		return nil, err
	}
	data := &tplData{
		st:           s,
		Organization: esc(s.r.organization),
		Device: deviceView{
			ID:           esc(s.d.ID),
			SerialNumber: esc(s.d.SerialNumber),
			DeviceName:   esc(s.d.DeviceName),
			Model:        esc(s.d.Model),
			OSVersion:    esc(s.d.OSVersion),
			Platform:     esc(string(s.d.Platform)),
		},
	}
	if s.u != nil {
		data.user = &userView{Username: esc(s.u.Username), Email: esc(s.u.Email), Name: esc(s.u.Name)}
	} else {
		data.user = &userView{}
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		if s.fatal != nil {
			return nil, s.fatal
		}
		return nil, fmt.Errorf("%w: template failed: %v", core.ErrInvalid, err)
	}
	if s.fatal != nil {
		return nil, s.fatal
	}
	return buf.Bytes(), nil
}

// parsePayload checks that content is a property list with the top-level
// keys every profile needs. The error never includes the content.
func parsePayload(content []byte) (map[string]any, error) {
	var top map[string]any
	if _, err := plist.Unmarshal(content, &top); err != nil {
		return nil, fmt.Errorf("%w: the result is not a property list: %v", core.ErrInvalid, err)
	}
	if id, ok := top["PayloadIdentifier"].(string); !ok || id == "" {
		return nil, fmt.Errorf("%w: the profile has no top-level PayloadIdentifier string", core.ErrInvalid)
	}
	if id, ok := top["PayloadUUID"].(string); !ok || id == "" {
		return nil, fmt.Errorf("%w: the profile has no top-level PayloadUUID string", core.ErrInvalid)
	}
	return top, nil
}

// Render implements core.Renderer.
func (r *Renderer) Render(ctx context.Context, p core.Profile, d core.Device, u *core.User) (core.Rendered, error) {
	s := &state{r: r, ctx: ctx, p: p, d: d, u: u}
	content, err := s.execute()
	if err != nil {
		return core.Rendered{}, err
	}
	if len(s.missing) > 0 {
		return core.Rendered{Missing: s.missing}, nil
	}
	top, err := parsePayload(content)
	if err != nil {
		return core.Rendered{}, err
	}
	sum := sha256.Sum256(content)
	return core.Rendered{
		Content:    content,
		Identifier: top["PayloadIdentifier"].(string),
		Hash:       hex.EncodeToString(sum[:]),
	}, nil
}

// Validate implements core.Renderer.
func (r *Renderer) Validate(p core.Profile) (core.TemplateInfo, error) {
	var info core.TemplateInfo
	if !idPattern.MatchString(p.ID) {
		return info, fmt.Errorf("%w: the ID %q must use only lower-case letters, digits and dashes", core.ErrInvalid, p.ID)
	}
	if strings.TrimSpace(p.Name) == "" {
		return info, fmt.Errorf("%w: the profile needs a name", core.ErrInvalid)
	}
	if len(p.Platforms) == 0 {
		return info, fmt.Errorf("%w: the profile needs at least one platform (macos, ios, ipados)", core.ErrInvalid)
	}
	for _, pl := range p.Platforms {
		switch pl {
		case core.PlatformMacOS, core.PlatformIOS, core.PlatformIPadOS:
		default:
			return info, fmt.Errorf("%w: unknown platform %q (use macos, ios or ipados)", core.ErrInvalid, pl)
		}
	}
	switch p.MacOSChannel {
	case "", core.ChannelDevice, core.ChannelUser:
	default:
		return info, fmt.Errorf("%w: macos_channel must be \"device\" or \"user\", not %q", core.ErrInvalid, p.MacOSChannel)
	}

	t, err := parseTemplate(p.Template, stubFuncs())
	if err != nil {
		return info, err
	}
	users, globals := map[string]bool{}, map[string]bool{}
	for _, tt := range t.Templates() {
		if tt.Tree == nil || tt.Tree.Root == nil {
			continue
		}
		if err := walkNode(tt.Tree.Root, users, globals); err != nil {
			return info, err
		}
	}
	info.UserSecrets = sortedKeys(users)
	info.GlobalSecrets = sortedKeys(globals)

	dev := core.Device{
		ID: "00000000-0000-0000-0000-000000000000", Platform: core.PlatformMacOS,
		SerialNumber: "SERIAL0000", DeviceName: "Placeholder device", Model: "Mac0,0", OSVersion: "0.0",
	}
	if len(p.Platforms) > 0 {
		dev.Platform = p.Platforms[0]
	}
	u := &core.User{Username: "placeholder", Email: "placeholder@example.com", Name: "Placeholder Person"}
	s := &state{r: r, ctx: context.Background(), p: p, d: dev, u: u, placeholder: true}
	content, err := s.execute()
	if err != nil {
		return info, err
	}
	top, err := parsePayload(content)
	if err != nil {
		return info, err
	}
	info.Identifier = top["PayloadIdentifier"].(string)
	info.PayloadTypes = []string{}
	if items, ok := top["PayloadContent"].([]any); ok {
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if typ, ok := m["PayloadType"].(string); ok {
					info.PayloadTypes = append(info.PayloadTypes, typ)
				}
			}
		}
	}
	return info, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func walkNode(n parse.Node, users, globals map[string]bool) error {
	switch n := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := walkNode(c, users, globals); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		return walkNode(n.Pipe, users, globals)
	case *parse.IfNode:
		return walkBranch(&n.BranchNode, users, globals)
	case *parse.RangeNode:
		return walkBranch(&n.BranchNode, users, globals)
	case *parse.WithNode:
		return walkBranch(&n.BranchNode, users, globals)
	case *parse.TemplateNode:
		return walkNode(n.Pipe, users, globals)
	case *parse.PipeNode:
		if n == nil {
			return nil
		}
		for i, cmd := range n.Cmds {
			if err := walkCommand(cmd, i > 0, users, globals); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkBranch(b *parse.BranchNode, users, globals map[string]bool) error {
	if err := walkNode(b.Pipe, users, globals); err != nil {
		return err
	}
	if err := walkNode(b.List, users, globals); err != nil {
		return err
	}
	if b.ElseList != nil {
		return walkNode(b.ElseList, users, globals)
	}
	return nil
}

func walkCommand(c *parse.CommandNode, piped bool, users, globals map[string]bool) error {
	for _, a := range c.Args {
		if p, ok := a.(*parse.PipeNode); ok {
			if err := walkNode(p, users, globals); err != nil {
				return err
			}
		}
	}
	if len(c.Args) == 0 {
		return nil
	}
	id, ok := c.Args[0].(*parse.IdentifierNode)
	if !ok {
		return nil
	}
	var target map[string]bool
	switch id.Ident {
	case fnSecret, fnSecretData:
		target = users
	case fnGlobal, fnGlobalData:
		target = globals
	default:
		return nil
	}
	if piped || len(c.Args) != 2 {
		return fmt.Errorf("%w: %s needs the secret's name written in quotes, like %s \"name\"", core.ErrInvalid, id.Ident, id.Ident)
	}
	lit, ok := c.Args[1].(*parse.StringNode)
	if !ok {
		return fmt.Errorf("%w: %s needs the secret's name written in quotes, like %s \"name\"", core.ErrInvalid, id.Ident, id.Ident)
	}
	target[lit.Text] = true
	return nil
}
