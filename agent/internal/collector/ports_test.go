package collector

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func procNetRow(i int, local, remote, state string, inode int) string {
	return fmt.Sprintf("  %d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 2 0000000000000000 0\n",
		i, local, remote, state, inode)
}

func TestCollectListeners(t *testing.T) {
	p := newFakeProc(t)
	p.file("net/tcp", procNetHeader+
		procNetRow(0, "00000000:1538", "00000000:0000", "0A", 100)+ // 0.0.0.0:5432 LISTEN
		procNetRow(1, "0100007F:0035", "00000000:0000", "0A", 101)+ // 127.0.0.1:53 LISTEN
		procNetRow(2, "0F02000A:0016", "0100000A:D2F0", "01", 102)) // established: not a listener
	p.file("net/tcp6", procNetHeader+
		procNetRow(0, "00000000000000000000000000000000:0016", "00000000000000000000000000000000:0000", "0A", 103)) // [::]:22
	p.file("net/udp", procNetHeader+
		procNetRow(0, "3500007F:0035", "00000000:0000", "07", 200)+ // 127.0.0.53:53 bound, unconnected
		procNetRow(1, "00000000:0044", "00000000:0000", "07", 201)+ // 0.0.0.0:68
		procNetRow(2, "00000000:0044", "00000000:0000", "07", 202)+ // 0.0.0.0:68 again (SO_REUSEPORT)
		procNetRow(3, "0F02000A:A3F1", "08080808:0035", "01", 203)+ // connected DNS client: not a listener
		procNetRow(4, "00000000:0000", "00000000:0000", "07", 204)) // unbound: not a listener
	// no udp6: IPv6 disabled is not an error

	p.symlink("10/fd/3", "socket:[100]")
	p.symlink("10/fd/4", "/dev/null")
	p.file("10/comm", "postgres\n")
	p.symlink("20/fd/7", "socket:[202]")
	p.file("20/comm", "dhclient\n")
	p.symlink("30/fd/1", "socket:[103]")
	p.file("30/comm", "sshd\n")

	res := CollectListeners(p.root)
	tcp, udp := res[TransportTCP], res[TransportUDP]
	if tcp.Err != nil || udp.Err != nil {
		t.Fatalf("errors: tcp=%v udp=%v", tcp.Err, udp.Err)
	}
	wantTCP := []Socket{
		{Proto: "tcp", LocalAddr: "127.0.0.1", Port: 53},
		{Proto: "tcp", LocalAddr: "0.0.0.0", Port: 5432, PID: 10, ProcessName: "postgres"},
		{Proto: "tcp6", LocalAddr: "::", Port: 22, PID: 30, ProcessName: "sshd"},
	}
	wantUDP := []Socket{
		{Proto: "udp", LocalAddr: "127.0.0.53", Port: 53},
		{Proto: "udp", LocalAddr: "0.0.0.0", Port: 68, PID: 20, ProcessName: "dhclient"},
	}
	if got := stripInodes(tcp.Sockets); !reflect.DeepEqual(got, wantTCP) {
		t.Errorf("tcp = %+v\nwant %+v", got, wantTCP)
	}
	if got := stripInodes(udp.Sockets); !reflect.DeepEqual(got, wantUDP) {
		t.Errorf("udp = %+v\nwant %+v", got, wantUDP)
	}
	if tcp.Truncated || udp.Truncated {
		t.Error("unexpected truncation")
	}
}

func TestCollectListenersCapAndErrors(t *testing.T) {
	p := newFakeProc(t)
	var b strings.Builder
	b.WriteString(procNetHeader)
	for i := 0; i < MaxListenersPerTransport+5; i++ {
		b.WriteString(procNetRow(i, fmt.Sprintf("00000000:%04X", 1000+i), "00000000:0000", "0A", 1000+i))
	}
	p.file("net/tcp", b.String())
	// udp is a directory: unreadable as a file, so only UDP fails.
	p.file("net/udp/x", "")

	res := CollectListeners(p.root)
	if tcp := res[TransportTCP]; tcp.Err != nil || !tcp.Truncated || len(tcp.Sockets) != MaxListenersPerTransport || tcp.Sockets[0].Port != 1000 {
		t.Errorf("tcp: err=%v truncated=%v n=%d", tcp.Err, tcp.Truncated, len(tcp.Sockets))
	}
	if udp := res[TransportUDP]; udp.Err == nil || udp.Sockets != nil {
		t.Errorf("udp: want error and no sockets, got %+v", udp)
	}
}

func TestHexToIP(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F":                         "127.0.0.1",
		"00000000":                         "0.0.0.0",
		"00000000000000000000000001000000": "::1",
		"0000000000000000FFFF00000100007F": "::ffff:127.0.0.1",
		"000080FE00000000FF005450B6AD1DFE": "fe80::5054:ff:fe1d:adb6",
		"zz":                               "zz",
	} {
		if got := hexToIP(in); got != want {
			t.Errorf("hexToIP(%s) = %s, want %s", in, got, want)
		}
	}
}

func stripInodes(s []Socket) []Socket {
	out := make([]Socket, len(s))
	for i, x := range s {
		x.inode = 0
		out[i] = x
	}
	return out
}
