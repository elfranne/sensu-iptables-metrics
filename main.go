package main

import (
	"bufio"
	"fmt"
	"log"
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

func executeCheck(event *corev2.Event) (int, error) {
	regex := regexp.MustCompile(`\s*(\d+)\s+(\d+).*?/\*\s+(\d+)\s+([A-Za-z0-9_\-\s+]+)\s+\*/`)
	out, err := exec.Command(plugin.bin, plugin.ftype, "-L", "-nvx").CombinedOutput()
	if err != nil {
		log.Fatalf("failed with %s %s\n", out, err)
	}
	rules := bufio.NewScanner(strings.NewReader(string(out)))
	for rules.Scan() {
		splitted := regex.FindStringSubmatch(rules.Text())
		// if len(splitted) > 0 {
		// 	fmt.Println(splitted)
		// }
		if len(splitted) == 5 {
			fmt.Printf("%s.iptables.packets.%s.%s %s %d\n", plugin.Scheme, splitted[3], strings.ReplaceAll(splitted[4], " ", "_"), splitted[1], time.Now().Unix())
			fmt.Printf("%s.iptables.bytes.%s.%s %s %d\n", plugin.Scheme, splitted[3], strings.ReplaceAll(splitted[4], " ", "_"), splitted[2], time.Now().Unix())
		}
	}
	return sensu.CheckStateOK, nil
}
