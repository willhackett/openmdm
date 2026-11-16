package mdm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"howett.net/plist"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"

	"openmdm/internal/core"
)

// reporter wraps the NanoMDM service and, after an inner call has
// succeeded, tells core.Events what happened. Whatever Events does, it
// cannot fail the device's request: panics are recovered and logged.
type reporter struct {
	service.CheckinAndCommandService
	events core.Events
	log    *slog.Logger
}

func (p *reporter) safely(what string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			p.log.Error("event handler panicked", "event", what, "panic", fmt.Sprint(rec))
		}
	}()
	fn()
}

// channelIDs gives the IDs NanoMDM uses for a message: the device channel
// ID, the user (or enrolment user) part if this is a user channel, and the
// ID of the channel itself. It repeats NanoMDM's own normalisation
// (service/nanomdm.normalize): "<device>" or "<device>:<user>".
func channelIDs(e *mdm.Enrollment) (deviceID, userID, enrollmentID string) {
	r := e.Resolved()
	if r == nil {
		return "", "", ""
	}
	deviceID = r.DeviceChannelID
	enrollmentID = deviceID
	if r.IsUserChannel {
		userID = r.UserChannelID
		enrollmentID = deviceID + ":" + userID
	}
	return
}

func certSHA256(r *mdm.Request) string {
	if r == nil || r.Certificate == nil {
		return ""
	}
	sum := sha256.Sum256(r.Certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func (p *reporter) checkin(r *mdm.Request, e *mdm.Enrollment) core.Checkin {
	deviceID, userID, enrollmentID := channelIDs(e)
	return core.Checkin{
		DeviceID:     deviceID,
		UserID:       userID,
		EnrollmentID: enrollmentID,
		CertSHA256:   certSHA256(r),
	}
}

// authenticateProps are the Authenticate keys we pass on.
type authenticateProps struct {
	Model       string `plist:"Model"`
	ProductName string `plist:"ProductName"`
	DeviceName  string `plist:"DeviceName"`
	OSVersion   string `plist:"OSVersion"`
}

func (p *reporter) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	if err := p.CheckinAndCommandService.Authenticate(r, m); err != nil {
		return err
	}
	c := p.checkin(r, &m.Enrollment)
	c.SerialNumber = m.SerialNumber
	var props authenticateProps
	if _, err := plist.Unmarshal(m.Raw, &props); err != nil {
		p.log.Debug("reading Authenticate properties", "err", err)
	}
	c.Model, c.ProductName, c.DeviceName, c.OSVersion = props.Model, props.ProductName, props.DeviceName, props.OSVersion
	p.safely("DeviceAuthenticated", func() { p.events.DeviceAuthenticated(r.Context(), c) })
	return nil
}

func (p *reporter) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	if err := p.CheckinAndCommandService.TokenUpdate(r, m); err != nil {
		return err
	}
	c := p.checkin(r, &m.Enrollment)
	p.safely("DeviceTokenUpdated", func() { p.events.DeviceTokenUpdated(r.Context(), c) })
	return nil
}

func (p *reporter) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	if err := p.CheckinAndCommandService.CheckOut(r, m); err != nil {
		return err
	}
	c := p.checkin(r, &m.Enrollment)
	p.safely("DeviceCheckedOut", func() { p.events.DeviceCheckedOut(r.Context(), c) })
	return nil
}

func (p *reporter) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	next, err := p.CheckinAndCommandService.CommandAndReportResults(r, m)
	if err != nil {
		return next, err
	}
	// An "Idle" report is the device asking for work; it answers nothing.
	if m.CommandUUID == "" || m.Status == "Idle" {
		return next, nil
	}
	deviceID, _, enrollmentID := channelIDs(&m.Enrollment)
	res := core.CommandResult{
		CommandUUID:  m.CommandUUID,
		EnrollmentID: enrollmentID,
		DeviceID:     deviceID,
		Status:       commandStatus(m.Status),
		ErrorText:    flattenErrorChain(m.ErrorChain),
		Raw:          m.Raw,
	}
	p.safely("CommandResulted", func() { p.events.CommandResulted(r.Context(), res) })
	return next, nil
}

// commandStatus maps the device's Status. CommandFormatError and anything
// unknown are errors: the command did not do what was asked.
func commandStatus(s string) core.CommandStatus {
	switch s {
	case "Acknowledged":
		return core.CommandAcknowledged
	case "NotNow":
		return core.CommandNotNow
	default:
		return core.CommandError
	}
}

// flattenErrorChain renders an ErrorChain as one line:
// "Profile failed (MCProfileErrorDomain 4001); Other (Domain 1)".
func flattenErrorChain(chain []mdm.ErrorChain) string {
	parts := make([]string, 0, len(chain))
	for _, e := range chain {
		desc := e.LocalizedDescription
		if desc == "" {
			desc = e.USEnglishDescription
		}
		desc = strings.Join(strings.Fields(desc), " ")
		var s string
		switch {
		case desc != "" && e.ErrorDomain != "":
			s = fmt.Sprintf("%s (%s %d)", desc, e.ErrorDomain, e.ErrorCode)
		case desc != "":
			s = fmt.Sprintf("%s (%d)", desc, e.ErrorCode)
		default:
			s = fmt.Sprintf("%s %d", e.ErrorDomain, e.ErrorCode)
		}
		parts = append(parts, strings.TrimSpace(s))
	}
	return strings.Join(parts, "; ")
}
