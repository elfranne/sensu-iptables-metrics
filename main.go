package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	corev2 "github.com/sensu/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	bin    string
	ftype  string
	Scheme string
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "metrics-iptables",
			Short:    "metrics for iptables",
			Keyspace: "sensu.io/plugins/metrics-iptables/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Path:      "bin",
			Argument:  "bin",
			Shorthand: "b",
			Default:   "/usr/sbin/xtables-legacy-multi",
			Usage:     "location of the firewall binary",
			Value:     &plugin.bin,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "ftype",
			Argument:  "ftype",
			Shorthand: "f",
			Default:   "iptables",
			Usage:     "type of firewall (generally iptables or iptables-nft)",
			Value:     &plugin.ftype,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "scheme",
			Argument:  "scheme",
			Shorthand: "s",
			Default:   "",
			Usage:     "Scheme to prepend metric",
			Value:     &plugin.Scheme,
		},
	}

	// ruleRE matches a rule line of `iptables -L -nvx` that carries a
	// `/* <id> <name> */` comment, capturing packets, bytes, id and name.
	// Chain headers and column headers do not match: they have no comment.
	ruleRE = regexp.MustCompile(`\s*(\d+)\s+(\d+).*?/\*\s+(\d+)\s+([A-Za-z0-9_\-\s+]+)\s+\*/`)
)

func main() {
	check := sensu.NewCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if plugin.Scheme == "" {
		return sensu.CheckStateWarning, fmt.Errorf("scheme is required")
	}
	return sensu.CheckStateOK, nil
}

// writeMetrics scans `iptables -L -nvx` output from r and writes graphite
// plaintext metrics to w: one packets line and one bytes line for every rule
// tagged with a `/* <id> <name> */` comment. Untagged rules, chain headers and
// column headers are ignored.
//
// The -x flag is load-bearing: without it iptables abbreviates counters
// ("571K"), which would be parsed as a plain 571.
func writeMetrics(w io.Writer, r io.Reader, scheme string, ts int64) error {
	rules := bufio.NewScanner(r)
	for rules.Scan() {
		matched := ruleRE.FindStringSubmatch(rules.Text())
		if len(matched) != 5 {
			continue
		}
		name := strings.ReplaceAll(matched[4], " ", "_")
		if _, err := fmt.Fprintf(w, "%s.iptables.packets.%s.%s %s %d\n", scheme, matched[3], name, matched[1], ts); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s.iptables.bytes.%s.%s %s %d\n", scheme, matched[3], name, matched[2], ts); err != nil {
			return err
		}
	}
	return rules.Err()
}

func executeCheck(event *corev2.Event) (int, error) {
	out, err := exec.Command(plugin.bin, plugin.ftype, "-L", "-nvx").CombinedOutput()
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("%s %s -L -nvx: %w: %s",
			plugin.bin, plugin.ftype, err, bytes.TrimSpace(out))
	}
	// One timestamp for the whole scrape, so every metric of a single run
	// shares it even if the scan crosses a second boundary.
	if err := writeMetrics(os.Stdout, bytes.NewReader(out), plugin.Scheme, time.Now().Unix()); err != nil {
		return sensu.CheckStateCritical, err
	}
	return sensu.CheckStateOK, nil
}
