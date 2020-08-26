// Package chronytime uses the Chrony time daemon to emulate TrueTime behavior.
//
// Chrony is an NTP-like time daemon that synchronizes the system clock to several
// time servers. Chrony maintains estimates of clock error which package chronytime
// uses to provide consistent time stamps.
package chronytime

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"
)

var networkOrder = binary.BigEndian

// #defines from chrony/candm.c
const (
	// UNIX domain socket might be available if we are running as chrony user or
	// root, but regular users will connect via UDP
	// const defaultCommandSocket = "/var/run/chrony/chronyd.sock"
	defaultCandMPort = 323

	// Packet types (request.pktType and response.PktType)
	pktTypeCmdRequest = 1
	pktTypeCmdReply   = 2

	// Commands (request.command and response.Command)
	cmdTracking = 33 // also used for waitSync

	// Replies (response.Reply)
	rpyNull     = 1
	rpyTracking = 5

	// Statuses
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
	cfloatCoefBits = ( /*unsafe.Sizeof(int32(0))*/ 4*8 - cfloatExpBits)
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
	sequence uint32
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

	// Present in the C structs, but only used by offsetof operator
	// to determine number of bytes to send. It is not itself transmitted.
	// EOR int32
}

func uncertaintyFromCorrectedTime(r trackingResponse) time.Duration {
	// https://listengine.tuxfamily.org/chrony.tuxfamily.org/chrony-users/2017/08/msg00014.html
	rootDelay := r.RootDelay.value()
	rootDispersion := r.RootDispersion.value()
	s := rootDispersion + (0.5 * rootDelay)
	ns := s * math.Pow(10, 9)
	return time.Duration(ns)
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

var responseBinarySize = binary.Size(response{})

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

// Response is a struct containing a time reading consisting of a timestamp and
// the associated uncertainty.
type Response struct {
	Now         time.Time
	Uncertainty time.Duration

	// For testing
	uncorrectedNow time.Time
	correction     time.Duration
}

// Get returns a Response or an error.
func (c *Client) Get() (Response, error) {
	r, err := c.trackingRequest()
	if err != nil {
		return Response{}, err
	}
	correctionNs := r.Tracking.CurrentCorrection.value() * math.Pow(10, 9)
	correction := time.Duration(correctionNs)
	now := time.Now()
	return Response{
		Now:            now.Add(correction),
		Uncertainty:    uncertaintyFromCorrectedTime(r.Tracking),
		uncorrectedNow: now,
		correction:     correction,
	}, nil
}

// Earliest returns the earliest time at which the Response could have been
// obtained.
func (r *Response) Earliest() time.Time {
	return r.Now.Add(-r.Uncertainty)
}

func (c *Client) trackingRequest() (*response, error) {
	r := request{
		version:  6,
		pktType:  pktTypeCmdRequest,
		command:  cmdTracking,
		attempt:  0,
		sequence: rand.Uint32(),
	}
	if err := binary.Write(c.conn, networkOrder, r); err != nil {
		return nil, err
	}
	buffer := make([]byte, 1024)
	rep := new(response)
	c.conn.SetDeadline(time.Now().Add(1 * time.Second))
	n, addr, err := c.conn.ReadFromUDP(buffer)
	if n == 0 {
		return nil, fmt.Errorf("empty read")
	}

	if n < responseBinarySize {
		// TODO: handle partial reads in a loop
		return nil, fmt.Errorf("short read: expected %d bytes, got %d bytes", binary.Size(rep), n)
	}

	if !sameUDPAddr(*addr, *c.addr) {
		return nil, fmt.Errorf("expected %+v, got %+v", *c.addr, *addr)
	}
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(buffer)
	if err := binary.Read(reader, networkOrder, rep); err != nil {
		return nil, err
	}
	if rep.Sequence != r.sequence {
		return nil, fmt.Errorf("expected sequence %d, got %d", r.sequence, rep.Sequence)
	}

	return rep, nil
}

// Close closes the client.
func (c *Client) Close() error {
	return c.conn.Close()
}

// WaitUntilAfter blocks until chronytime is sure the current time is after t.
// If an error occurs while waiting, the operation is aborted and the error is returned.
//
// Use context.WithTimeout to limit how long to wait. Do not try to do math using
// time.Now() and t as this does not respect uncertainty semantics.
func (c *Client) WaitUntilAfter(ctx context.Context, t time.Time) error {
	for {
		r, err := c.Get()
		if err != nil {
			return err
		}
		if r.Earliest().After(t) {
			break
		}
		select {
		case <-time.After(t.Sub(r.Earliest())):
			continue
		case <-ctx.Done():
			return context.Canceled
		}
	}
	return nil
}
