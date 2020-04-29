// Package chronytime uses the Chrony time daemon to emulate TrueTime behavior.
//
// Chrony is an NTP-like time daemon that synchronizes the system clock to several
// time servers. Chrony maintains estimates of clock error which package chronytime
// uses to provide consistent time stamps.
package chronytime

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
	"unsafe"
)

// UNIX domain socket might be available if we are running as chrony user or
// root, but regular users will connect via UDP
// const defaultCommandSocket = "/var/run/chrony/chronyd.sock"
const defaultCandMPort = 323

var networkOrder = binary.BigEndian

// Packet types (request.pktType and response.PktType)
const (
	pktTypeCmdRequest = 1
	pktTypeCmdReply   = 2
)

// Commands (request.command and response.Command)
const (
	cmdTracking = 33 // also used for waitSync
)

// Replies (response.Reply)
const (
	rpyNull     = 1
	rpyTracking = 5
)

// Statuses
const (
	sttSuccess = 0
)

type timeSpec struct {
	SecHigh uint32
	SecLow  uint32
	Nsec    uint32
}

func (t *timeSpec) Time() time.Time {
	return time.Unix((int64(t.SecHigh)<<32)+int64(t.SecLow), int64(t.Nsec))
}

const (
	ipAddrFamilyUnspec = 0
	ipAddrFamilyINET4  = 1
	ipAddrFamilyINET6  = 2
	ipAddrFamilyID     = 3
)

type ipAddr struct {
	Addr    [16]byte // ipv4 - 4 bytes, ipv6 - 16 bytes, id - 4 bytes
	Family  uint16
	Padding uint16
}

/* 32-bit floating-point format consisting of 7-bit signed exponent
   and 25-bit signed coefficient without hidden bit.
   The result is calculated as: 2^(exp - 25) * coef */
type cfloat struct {
	F int32
}

const (
	cfloatExpBits  = 7
	cfloatExpMin   = (-(1 << (cfloatExpBits - 1)))
	cfloatExpMax   = (-cfloatExpMin - 1)
	cfloatCoefBits = (unsafe.Sizeof(int32(0))*8 - cfloatExpBits)
	cfloatCoefMin  = (-(1 << (cfloatCoefBits - 1)))
	cfloatCoefMax  = (-cfloatCoefMin - 1)
)

func (f *cfloat) value() float64 {
	var exp, coef int32
	x := uint32(f.F)
	exp = int32(x >> cfloatCoefBits)
	if exp >= 1<<(cfloatExpBits-1) {
		exp -= 1 << cfloatExpBits
	}
	exp -= int32(cfloatCoefBits)

	coef = int32(x % (1 << cfloatCoefBits))
	if coef >= 1<<(cfloatCoefBits-1) {
		coef -= 1 << cfloatCoefBits
	}

	return float64(coef) * math.Pow(2.0, float64(exp))
}

type request struct {
	version  uint8
	pktType  uint8
	res1     uint8
	res2     uint8
	command  uint16
	attempt  uint16
	sequence [4]byte
	pad1     [8]byte

	// union of request structs, largest of which is REQ_NTP_Source (93 bytes)
	pad2 [93]byte

	// actual padding to prevent data amplification attacks
	padding [396]byte
}

type trackingResponse struct {
	RefID              uint32
	Addr               ipAddr
	Stratum            uint16
	LeapStatus         uint16
	RefTime            timeSpec
	CurrentCorrection  cfloat
	LastOffset         cfloat
	RmsOffset          cfloat
	FreqPPM            cfloat
	ResidFreqPPM       cfloat
	SkewPPM            cfloat
	RootDelay          cfloat
	RootDispersion     cfloat
	LastUpdateInterval cfloat
	EOR                int32
}

func uncertainty(r trackingResponse) time.Duration {
	// https://chrony.tuxfamily.org/doc/3.5/chronyc.html
	correction := r.CurrentCorrection.value()
	rootDelay := r.RootDelay.value()
	rootDispersion := r.RootDispersion.value()
	s := math.Abs(correction) + rootDispersion + (0.5 * rootDelay)
	return time.Duration(s) * time.Second
}

type response struct {
	Version  uint8
	PktType  uint8
	Res1     uint8
	Res2     uint8
	Command  uint16
	Reply    uint16
	Status   uint16
	Pad1     uint16
	Pad2     uint16
	Pad3     uint16
	Sequence uint32
	Pad4     uint32
	Pad5     uint32

	// in C: union of lots of response types, we just use trackingResponse
	Tracking trackingResponse
}

// Client is a chronytime client.
type Client struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

// NewClient creates a new chronytime client and attempts to connect to a local
// chronyd instance.
func NewClient() (*Client, error) {
	s, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", defaultCandMPort))
	conn, err := net.DialUDP("udp4", nil, s)
	if err != nil {
		return nil, err
	}
	c := &Client{addr: s, conn: conn}

	if err := c.waitSync(); err != nil {
		return nil, err
	}

	return c, nil
}

func sameUDPAddr(a1, a2 net.UDPAddr) bool {
	if a1.IP.Equal(a2.IP) &&
		a1.Port == a2.Port &&
		a1.Zone == a2.Zone {
		return true
	}
	return false
}

func (c *Client) waitSync() error {
	attempts := 0
	maxAttempts := 3
	for {
		attempts++
		if attempts > maxAttempts {
			return fmt.Errorf("max attempts exceeded waiting for sync")
		}
		r, err := c.trackingRequest()
		if err != nil {
			return err
		}
		// no sync
		if r.Tracking.Addr.Family == ipAddrFamilyUnspec {
			continue
		}
		// local sync
		if r.Tracking.RefID == 0 || r.Tracking.RefID == 0x7f7f0101 /* LOCAL refid */ {
			continue
		}
		// too much uncertainty
		if uncertainty(r.Tracking) > (20 * time.Millisecond) {
			continue
		}
		// bad packet or parse
		if r.Tracking.EOR != 0 {
			continue
		}
		break
	}
	return nil
}

func (c *Client) trackingRequest() (*response, error) {
	r := request{
		version: 6,
		pktType: pktTypeCmdRequest,
		command: cmdTracking,
		attempt: 0,
	}
	rand.Read(r.sequence[:])
	if err := binary.Write(c.conn, networkOrder, r); err != nil {
		return nil, err
	}
	buffer := make([]byte, 1024)
	for {
		c.conn.SetDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := c.conn.ReadFromUDP(buffer)
		if n == 0 {
			return nil, fmt.Errorf("empty read")
		}
		if !sameUDPAddr(*addr, *c.addr) {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	reader := bytes.NewReader(buffer)
	rep := new(response)
	if err := binary.Read(reader, networkOrder, rep); err != nil {
		return nil, err
	}
	return rep, nil
}

// Close closes the client.
func (c *Client) Close() error {
	return c.conn.Close()
}

// WaitUntilAfter blocks until chronytime is sure the current time is after t.
// If an error occurs while waiting, the operation is aborted and the error is returned.
func (c *Client) WaitUntilAfter(t time.Time) error {
	for {
		r, err := c.trackingRequest()
		if err != nil {
			return err
		}
		now := time.Now()
		eps := uncertainty(r.Tracking)
		earliest := now.Add(-eps)
		if earliest.After(t) {
			break
		}
		time.Sleep(t.Sub(earliest))
	}
	return nil
}

// PrepareFunc is a function (usually a closure) that prepares a task to be consistently
// ordered. If PrepareFunc returns a non-nil error, the task is cancelled.
type PrepareFunc func() error

// CommitFunc is a function (usually a closure) that commits a task as though it occurred
// at the provided timestamp.
type CommitFunc func(time.Time) error

// ConsistentOperation executes an exteranlly consistent operation in two parts.
//
// First, pf is called. Typically, pf will acquire resources (files, locks) to ensure the
// completion of the operation. If pf returns a non-nil error, ConsistentOperation does
// not call cf and returns the error. Any required cleanup should be completed before pf
// returns.
//
// If pf returns nil, ConsistentOperation obtains a timestamp and passes it to cf. Typically,
// cf will commit the operation to databases or files using the provided timestamp. If cf
// returns a non-nill error, ConsistentOperation returns that error. Any required cleanup
// should be completed before cf returns. If cf returns nil, ConsistentOperation will wait
// out the uncertainty in the timestamp and then return the timestamp.
//
// To ensure consistency, success should not be reported to any external clients until after
// ConsistentOperation has returned.
func (c *Client) ConsistentOperation(pf PrepareFunc, cf CommitFunc) (time.Time, error) {
	if err := pf(); err != nil {
		return time.Time{}, err
	}
	t := time.Now()
	if err := cf(t); err != nil {
		return time.Time{}, err
	}
	c.WaitUntilAfter(t)
	return t, nil
}
