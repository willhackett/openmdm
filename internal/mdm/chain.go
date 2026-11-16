package mdm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
)

// idGuard is the outermost service in the chain. NanoMDM's file storage uses
// the enrollment ID as a directory name, and the IDs come from the device's
// own message, so a hostile (but enrolled) device must not be able to name a
// path. It refuses anything that could not be a plain name before any other
// service sees it. ":" is refused too: it joins the device and user parts of
// a user-channel ID, so allowing it would let one device collide with
// another's user channel.
type idGuard struct {
	next service.CheckinAndCommandService
}

const maxIDPart = 200

func validIDPart(s string) bool {
	if s == "" {
		return true // absent; the resolver decides whether that is allowed
	}
	if len(s) > maxIDPart || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, "/\\:\x00")
}

func guard(e *mdm.Enrollment) error {
	for _, p := range []string{e.UDID, e.UserID, e.UserShortName, e.EnrollmentID, e.EnrollmentUserID} {
		if !validIDPart(p) {
			return service.NewHTTPStatusError(http.StatusBadRequest, errors.New("invalid enrollment identifier"))
		}
	}
	return nil
}

func (g idGuard) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	if err := guard(&m.Enrollment); err != nil {
		return err
	}
	return g.next.Authenticate(r, m)
}

func (g idGuard) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	if err := guard(&m.Enrollment); err != nil {
		return err
	}
	return g.next.TokenUpdate(r, m)
}

func (g idGuard) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	if err := guard(&m.Enrollment); err != nil {
		return err
	}
	return g.next.CheckOut(r, m)
}

func (g idGuard) SetBootstrapToken(r *mdm.Request, m *mdm.SetBootstrapToken) error {
	if err := guard(&m.Enrollment); err != nil {
		return err
	}
	return g.next.SetBootstrapToken(r, m)
}

func (g idGuard) GetBootstrapToken(r *mdm.Request, m *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	if err := guard(&m.Enrollment); err != nil {
		return nil, err
	}
	return g.next.GetBootstrapToken(r, m)
}

func (g idGuard) UserAuthenticate(r *mdm.Request, m *mdm.UserAuthenticate) ([]byte, error) {
	if err := guard(&m.Enrollment); err != nil {
		return nil, err
	}
	return g.next.UserAuthenticate(r, m)
}

func (g idGuard) DeclarativeManagement(r *mdm.Request, m *mdm.DeclarativeManagement) ([]byte, error) {
	if err := guard(&m.Enrollment); err != nil {
		return nil, err
	}
	return g.next.DeclarativeManagement(r, m)
}

func (g idGuard) GetToken(r *mdm.Request, m *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	if err := guard(&m.Enrollment); err != nil {
		return nil, err
	}
	return g.next.GetToken(r, m)
}

func (g idGuard) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	if err := guard(&m.Enrollment); err != nil {
		return nil, err
	}
	return g.next.CommandAndReportResults(r, m)
}
