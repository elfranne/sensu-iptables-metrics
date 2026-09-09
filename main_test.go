package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// testTS is a fixed timestamp so expected output is deterministic.
const testTS = int64(1757404800)

// fixtureFilter is real `iptables -L -nvx` output (iptables v1.8.10), with
// counters edited for readability. The trailing spaces on the column-header
// lines and on untagged rules with no match extensions are genuine — do not
// strip them, they are part of what the parser has to cope with.
const fixtureFilter = `Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination         
     400   571200 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* 10 http traffic */
   12345  9876543 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 ctstate NEW /* 11 https_traffic */
       0        0 ACCEPT     17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53
       7      420 ACCEPT     6    --  *      *       10.20.30.40          192.168.100.200      tcp dpt:8080 /* 12 db-link+1 */
       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* just a note */

Chain FORWARD (policy DROP 12 packets, 3456 bytes)
    pkts      bytes target     prot opt in     out     source               destination         
       3      180 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 13 blocked p2p */

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination         
18446744073709551615 18446744073709551615 ACCEPT     0    --  *      eth0    0.0.0.0/0            0.0.0.0/0            /* 14 out bound */
`

// fixtureEmpty is a ruleset with chains but no rules at all.
const fixtureEmpty = `Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination         

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination         
`

// run is a shorthand for writeMetrics against an in-memory reader/writer.
func run(t *testing.T, in string) string {
	t.Helper()
	var buf strings.Builder
	if err := writeMetrics(&buf, strings.NewReader(in), "web01", testTS); err != nil {
		t.Fatalf("writeMetrics returned unexpected error: %v", err)
	}
	return buf.String()
}

func TestWriteMetricsFullRuleset(t *testing.T) {
	want := `web01.iptables.packets.10.http_traffic 400 1757404800
web01.iptables.bytes.10.http_traffic 571200 1757404800
web01.iptables.packets.11.https_traffic 12345 1757404800
web01.iptables.bytes.11.https_traffic 9876543 1757404800
web01.iptables.packets.12.db-link+1 7 1757404800
web01.iptables.bytes.12.db-link+1 420 1757404800
web01.iptables.packets.13.blocked_p2p 3 1757404800
web01.iptables.bytes.13.blocked_p2p 180 1757404800
web01.iptables.packets.14.out_bound 18446744073709551615 1757404800
web01.iptables.bytes.14.out_bound 18446744073709551615 1757404800
`
	if got := run(t, fixtureFilter); got != want {
		t.Errorf("output mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteMetricsEmptyRuleset(t *testing.T) {
	if got := run(t, fixtureEmpty); got != "" {
		t.Errorf("expected no metrics from a ruleset with no rules, got:\n%s", got)
	}
}

func TestWriteMetricsNoInput(t *testing.T) {
	if got := run(t, ""); got != "" {
		t.Errorf("expected no metrics from empty input, got:\n%s", got)
	}
}

// TestWriteMetricsIgnoredLines covers everything that must not produce metrics.
func TestWriteMetricsIgnoredLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{
			name: "chain header with zero policy counters",
			in:   `Chain INPUT (policy ACCEPT 0 packets, 0 bytes)`,
		},
		{
			// "12 packets, 3456 bytes" are two integers on one line; the rule
			// still must not match, because there is no /* */ comment.
			name: "chain header with non-zero policy counters",
			in:   `Chain FORWARD (policy DROP 12 packets, 3456 bytes)`,
		},
		{
			name: "user-defined chain header",
			in:   `Chain DOCKER-USER (1 references)`,
		},
		{
			name: "column header",
			in:   `    pkts      bytes target     prot opt in     out     source               destination         `,
		},
		{
			name: "blank line",
			in:   ``,
		},
		{
			name: "rule without a comment",
			in:   `       0        0 ACCEPT     17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53`,
		},
		{
			name: "jump rule with trailing padding and no comment",
			in:   `       0        0 MYCHAIN    0    --  *      *       0.0.0.0/0            0.0.0.0/0           `,
		},
		{
			name: "comment without a leading id",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* just a note */`,
		},
		{
			// executeCheck uses CombinedOutput, so iptables' stderr warnings
			// land in the parsed stream.
			name: "iptables stderr warning",
			in:   `# Warning: iptables-legacy tables present, use iptables-legacy to see them`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, tt.in); got != "" {
				t.Errorf("expected no output, got:\n%s", got)
			}
		})
	}
}

// TestWriteMetricsRuleLines covers lines that must produce metrics.
func TestWriteMetricsRuleLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "basic tagged rule",
			in:   `     400   571200 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* 10 http traffic */`,
			want: "web01.iptables.packets.10.http_traffic 400 1757404800\n" +
				"web01.iptables.bytes.10.http_traffic 571200 1757404800\n",
		},
		{
			// iptables <= 1.8.7 prints the protocol by name, not by number.
			name: "protocol printed as a name",
			in:   `     400   571200 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* 10 http traffic */`,
			want: "web01.iptables.packets.10.http_traffic 400 1757404800\n" +
				"web01.iptables.bytes.10.http_traffic 571200 1757404800\n",
		},
		{
			name: "extra match fields before the comment",
			in:   `   12345  9876543 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 ctstate NEW /* 11 https_traffic */`,
			want: "web01.iptables.packets.11.https_traffic 12345 1757404800\n" +
				"web01.iptables.bytes.11.https_traffic 9876543 1757404800\n",
		},
		{
			// Regression guard: the source and destination columns are full of
			// digits, and must never be mistaken for the counters.
			name: "digit-rich source and destination addresses",
			in:   `       7      420 ACCEPT     6    --  *      *       10.20.30.40          192.168.100.200      tcp dpt:8080 /* 12 db-link+1 */`,
			want: "web01.iptables.packets.12.db-link+1 7 1757404800\n" +
				"web01.iptables.bytes.12.db-link+1 420 1757404800\n",
		},
		{
			// Guard against anyone "improving" this with strconv.Atoi: these
			// counters are uint64 and overflow a signed int on 64-bit.
			name: "uint64 max counters are passed through verbatim",
			in:   `18446744073709551615 18446744073709551615 ACCEPT     0    --  *      eth0    0.0.0.0/0            0.0.0.0/0            /* 14 out bound */`,
			want: "web01.iptables.packets.14.out_bound 18446744073709551615 1757404800\n" +
				"web01.iptables.bytes.14.out_bound 18446744073709551615 1757404800\n",
		},
		{
			name: "underscore, hyphen and plus in the name",
			in:   `      12      480 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 18 a_b-c+d */`,
			want: "web01.iptables.packets.18.a_b-c+d 12 1757404800\n" +
				"web01.iptables.bytes.18.a_b-c+d 480 1757404800\n",
		},
		{
			// Only the first token is the id; a number later in the name stays
			// part of the name.
			name: "numeric token inside the name",
			in:   `      12      480 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 19 20 http */`,
			want: "web01.iptables.packets.19.20_http 12 1757404800\n" +
				"web01.iptables.bytes.19.20_http 480 1757404800\n",
		},
		{
			name: "text after the comment (DNAT target)",
			in:   `       0        0 DNAT       6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 /* 30 dnat web */ to:10.0.0.5:8080`,
			want: "web01.iptables.packets.30.dnat_web 0 1757404800\n" +
				"web01.iptables.bytes.30.dnat_web 0 1757404800\n",
		},
		{
			name: "LOG rule whose prefix contains digits",
			in:   `       0        0 LOG        0    --  *      *       0.0.0.0/0            0.0.0.0/0            LOG flags 0 level 4 prefix "fw " /* 21 logged */`,
			want: "web01.iptables.packets.21.logged 0 1757404800\n" +
				"web01.iptables.bytes.21.logged 0 1757404800\n",
		},
		{
			name: "limit rule containing a slash",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            limit: avg 3/min burst 5 /* 24 limited */`,
			want: "web01.iptables.packets.24.limited 0 1757404800\n" +
				"web01.iptables.bytes.24.limited 0 1757404800\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, tt.in); got != tt.want {
				t.Errorf("output mismatch\ngot:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

// TestWriteMetricsKnownQuirks pins down behaviour that is arguably wrong but
// currently shipped. These are characterization tests, not endorsements: the
// metric names they describe are already in users' dashboards, so changing them
// is a breaking change. If you fix the regex, update these deliberately.
func TestWriteMetricsKnownQuirks(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		why  string
	}{
		{
			name: "repeated and trailing spaces leak into the metric name",
			in:   `       3      180 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 13  double  space  name  */`,
			want: "web01.iptables.packets.13.double__space__name_ 3 1757404800\n" +
				"web01.iptables.bytes.13.double__space__name_ 180 1757404800\n",
			why: "each space becomes an underscore, so runs of spaces double up and a trailing space becomes a trailing underscore",
		},
		{
			name: "whitespace-only name still emits a metric",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 12    */`,
			want: "web01.iptables.packets.12._ 0 1757404800\n" +
				"web01.iptables.bytes.12._ 0 1757404800\n",
			why: "a comment of an id plus three or more spaces yields a metric literally named _",
		},
		{
			name: "id followed by exactly two spaces is rejected",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 13  */`,
			want: "",
			why:  "inconsistent with the three-space case above, which does emit",
		},
		{
			name: "id with no name is rejected",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 12 */`,
			want: "",
			why:  "the name group requires at least one character",
		},
		{
			name: "colon in the name is silently dropped",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 14 web:80 */`,
			want: "",
			why:  "': ' is outside the name character class, so the whole rule is skipped with no diagnostic",
		},
		{
			name: "dot in the name is silently dropped",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 15 api.example.com */`,
			want: "",
			why:  "a dot would also nest the metric a level deeper in graphite, so rejecting it is defensible",
		},
		{
			name: "slash in the name is silently dropped",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 16 rule/alt */`,
			want: "",
			why:  "'/' is outside the name character class",
		},
		{
			name: "non-ASCII in the name is silently dropped",
			in:   `       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 17 accent-é */`,
			want: "",
			why:  "the name character class is ASCII-only",
		},
		{
			// -x is hard-coded in executeCheck, so this is unreachable today.
			// The test documents why it must stay that way.
			name: "abbreviated counters without -x are truncated",
			in:   `  400  571K ACCEPT     1    --  lo     *       0.0.0.0/0            0.0.0.0/0            /* 20 loopback icmp */`,
			want: "web01.iptables.packets.20.loopback_icmp 400 1757404800\n" +
				"web01.iptables.bytes.20.loopback_icmp 571 1757404800\n",
			why: "571K parses as 571, a 1000x under-report; -x is what prevents this",
		},
		{
			// Reachable via --bin /usr/sbin/iptables --ftype --line-numbers.
			name: "line numbers shift every capture by one column",
			in:   `1          55     6600 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            /* 10 http traffic */`,
			want: "web01.iptables.packets.10.http_traffic 1 1757404800\n" +
				"web01.iptables.bytes.10.http_traffic 55 1757404800\n",
			why: "the regex is not anchored, so the line number is read as the packet count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, tt.in); got != tt.want {
				t.Errorf("output mismatch (%s)\ngot:\n%s\nwant:\n%s", tt.why, got, tt.want)
			}
		})
	}
}

// TestWriteMetricsSingleTimestamp guards the invariant that one scrape produces
// one timestamp, so the packets and bytes rows of a rule can never straddle a
// second boundary.
func TestWriteMetricsSingleTimestamp(t *testing.T) {
	out := run(t, fixtureFilter)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 metric lines, got %d", len(lines))
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("malformed graphite line %q: want 3 fields, got %d", line, len(fields))
		}
		if fields[2] != "1757404800" {
			t.Errorf("line %q has timestamp %s, want 1757404800", line, fields[2])
		}
	}
}

// errReader fails partway through, standing in for a read error on the pipe.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestWriteMetricsReadError(t *testing.T) {
	sentinel := errors.New("boom")
	err := writeMetrics(io.Discard, errReader{sentinel}, "web01", testTS)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected the read error to be returned, got %v", err)
	}
}

// errWriter fails on the first write, standing in for a closed stdout.
type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

func TestWriteMetricsWriteError(t *testing.T) {
	sentinel := errors.New("pipe closed")
	err := writeMetrics(errWriter{sentinel}, strings.NewReader(fixtureFilter), "web01", testTS)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected the write error to be returned, got %v", err)
	}
}

func TestCheckArgs(t *testing.T) {
	original := plugin.Scheme
	t.Cleanup(func() { plugin.Scheme = original })

	tests := []struct {
		name      string
		scheme    string
		wantState int
		wantErr   bool
	}{
		{name: "scheme provided", scheme: "web01", wantState: sensu.CheckStateOK, wantErr: false},
		{name: "scheme missing", scheme: "", wantState: sensu.CheckStateWarning, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin.Scheme = tt.scheme
			state, err := checkArgs(nil)
			if state != tt.wantState {
				t.Errorf("state = %d, want %d", state, tt.wantState)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
