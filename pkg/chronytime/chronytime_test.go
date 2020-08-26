package chronytime

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	c, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	r, err := c.Get()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if r.Now.Sub(now) > 100*time.Millisecond {
		t.Errorf("timestamps differ: %s, %s", now, r.Now)
	}
}

type cfloatCase struct {
	f    int32
	want float64
	ulp  uint64
}

func TestCFloat(t *testing.T) {
	cases := []cfloatCase{
		{f: -320148152, want: 0.000448087, ulp: 1e10},
		{f: -349885382, want: -0.000208690, ulp: 1e10},
		{f: -356455327, want: 0.000183986, ulp: 1e10},
		{f: 182955620, want: 14.480, ulp: 1e11},
		{f: -213802485, want: -0.003, ulp: 1e15},
		{f: -87438093, want: 0.049, ulp: 1e14},
		{f: -154422419, want: 0.012432915, ulp: 1e8},
		{f: -254273351, want: 0.001648686, ulp: 1e8},
		{f: 411118241, want: 1033.3, ulp: 1e12},
	}
	for _, c := range cases {
		cf := cfloat{F: c.f}
		if !equalULP(cf.value(), c.want, c.ulp) {
			t.Errorf("want: %f, got %f", c.want, cf.value())
		}
	}
}

func equalULP(a, b float64, ulp uint64) bool {
	steps := (b - a) / (math.Nextafter(a, b) - a)
	usteps := uint64(math.Trunc(steps))
	if usteps <= ulp {
		return true
	}
	return false
}

/*
	$ strace -f -e trace=network -x -s 10000 chronyc tracking
	< strace binary data --> testVec >
	Reference ID    : CE6C0084 (ntp2.torix.ca)
	Stratum         : 2
	Ref time (UTC)  : Tue Apr 28 23:01:19 2020
	System time     : 0.000448087 seconds slow of NTP time
	Last offset     : -0.000208690 seconds
	RMS offset      : 0.000183986 seconds
	Frequency       : 14.480 ppm fast
	Residual freq   : -0.003 ppm
	Skew            : 0.049 ppm
	Root delay      : 0.012432915 seconds
	Root dispersion : 0.001648686 seconds
	Update interval : 1033.3 seconds
	Leap status     : Normal
*/
var testVec = []byte("\x06\x02\x00\x00\x00\x21\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\xa2\x15\x69\x52\x00\x00\x00\x00\x00\x00\x00\x00\xce\x6c\x00\x84\xce\x6c\x00\x84\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x5e\xa8\xb5\xbf\x1c\x98\xf9\xc4\xec\xea\xed\x48\xeb\x25\x2c\x3a\xea\xc0\xec\x61\x0a\xe7\xae\x64\xf3\x41\xa2\x0b\xfa\xc9\xcc\xf3\xf6\xcb\xb3\x6d\xf0\xd8\x18\xb9\x18\x81\x2a\xa1")
var testRep = response{
	Version:  6,
	PktType:  pktTypeCmdReply,
	Command:  cmdTracking,
	Reply:    rpyTracking,
	Status:   sttSuccess,
	Sequence: 2719312210,
	Tracking: trackingResponse{
		RefID: 3463184516,
		Addr: ipAddr{
			Addr:   [16]byte{206, 108, 0, 132, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Family: 1,
		},
		Stratum:    2,
		LeapStatus: 0,
		RefTime: timeSpec{
			SecHigh: 0,
			SecLow:  1588114879,
			Nsec:    479787460,
		},
		CurrentCorrection:  cfloat{F: -320148152},
		LastOffset:         cfloat{F: -349885382},
		RmsOffset:          cfloat{F: -356455327},
		FreqPPM:            cfloat{F: 182955620},
		ResidFreqPPM:       cfloat{F: -213802485},
		SkewPPM:            cfloat{F: -87438093},
		RootDelay:          cfloat{F: -154422419},
		RootDispersion:     cfloat{F: -254273351},
		LastUpdateInterval: cfloat{F: 411118241},
	},
}

func TestUncertainty(t *testing.T) {
	x := 8313231 * time.Nanosecond
	if u := uncertainty(testRep.Tracking); u != x {
		t.Errorf("expected uncertainty %s, got %s", x.String(), u.String())
	}
}

func TestResponseParse(t *testing.T) {
	reader := bytes.NewReader(testVec)
	rep := new(response)
	if err := binary.Read(reader, networkOrder, rep); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&testRep, rep) {
		t.Logf("Wanted: %+v", testRep)
		t.Errorf("Got: %+v", rep)
	}
	rt := rep.Tracking.RefTime.Time().UTC().Format(time.ANSIC)
	wantrts := "Tue Apr 28 23:01:19 2020"
	if rt != wantrts {
		t.Errorf("Wanted: %s, got %s", wantrts, rt)
	}
	rccs := rep.Tracking.CurrentCorrection.value()
	rccns := rccs * math.Pow(10, 9)
	rcc := time.Duration(rccns)
	wantcc := time.Duration(448087 * time.Nanosecond)
	if rcc != wantcc {
		t.Errorf("Wanted: %v, got %v", wantcc, rcc)
	}
}

func TestResponse(t *testing.T) {
	c, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Get()
	if err != nil {
		t.Fatal(err)
	}
	et := r.uncorrectedNow.Add(r.correction)
	d := et.Sub(r.Now)
	if d < 0 {
		d = -d
	}
	if d > 0 {
		t.Errorf("expected %s, got %s, diff %s", et, r.Now, d)
	}
	earliest := r.Earliest()
	ee := et.Add(-r.Uncertainty)
	d = ee.Sub(earliest)
	if d < 0 {
		d = -d
	}
	if d > 0 {
		t.Errorf("expected %s, got %s, diff %s", ee, earliest, d)
	}
}

func TestWaitUntilAfter(t *testing.T) {
	c, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}

	// Success
	r, err := c.Get()
	if err != nil {
		t.Fatal(err)
	}
	target := r.Now.Add(10 * time.Nanosecond)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = c.WaitUntilAfter(ctx, target)
	if err != nil {
		t.Error(err)
	}

	// Force timeout
	r, err = c.Get()
	if err != nil {
		t.Fatal(err)
	}
	target = r.Now.Add(100 * time.Millisecond)
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Nanosecond)
	defer cancel()
	err = c.WaitUntilAfter(ctx, target)
	if err != context.Canceled {
		t.Errorf("expected context cancellation error, got %s", err)
	}
}

func BenchmarkFetch(b *testing.B) {
	c, err := NewClient()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Get(); err != nil {
			b.Fatal(err)
		}
	}
}
