[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/elfranne/sensu-iptables-metrics)
![Go Test](https://github.com/elfranne/sensu-iptables-metrics/workflows/Go%20Test/badge.svg)
![Go Lint](https://github.com/elfranne/sensu-iptables-metrics/workflows/Go%20Lint/badge.svg)
![goreleaser](https://github.com/elfranne/sensu-iptables-metrics/workflows/goreleaser/badge.svg)

# sensu-iptables-metrics

## Table of Contents
- [Overview](#overview)
- [How it works](#how-it-works)
  - [Tagging your rules](#tagging-your-rules)
  - [Output format](#output-format)
- [Usage examples](#usage-examples)
  - [Help output](#help-output)
  - [Command line](#command-line)
- [Configuration](#configuration)
  - [Asset registration](#asset-registration)
  - [Check definition](#check-definition)
  - [Permissions](#permissions)
- [Installation from source](#installation-from-source)
- [Contributing](#contributing)

## Overview

`sensu-iptables-metrics` is a [Sensu Check][6] that reads the packet and byte counters
attached to your firewall rules and emits them as [Graphite plaintext][11] metrics.

Rather than reporting on every rule in the ruleset — which produces unstable metric names as
soon as a rule is inserted or reordered — the plugin only reports on rules you have explicitly
tagged with a comment. That makes the metric names stable, and lets you decide exactly which
traffic is worth graphing.

It supports both the legacy `iptables` and the nftables-backed `iptables-nft` backends through
the `--bin` and `--ftype` flags.

## How it works

The plugin runs the equivalent of:

```
/usr/sbin/xtables-legacy-multi iptables -L -nvx
```

and scans the output for rules carrying a comment of the form `/* <id> <name> */`, where
`<id>` is a number and `<name>` is a label. Both the packet and byte counters of every matching
rule are emitted. Untagged rules and chain headers are ignored.

`-x` is what makes this reliable: it prints exact counters, so you never get the `1234K` /
`5M` rounding that plain `-L -nv` produces.

### Tagging your rules

Add a comment to any rule you want measured, using the `comment` match:

```
iptables -A INPUT -p tcp --dport 80 -m comment --comment "10 http" -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m comment --comment "20 https" -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m comment --comment "30 ssh admin" -j ACCEPT
```

The leading number is a sort key: it becomes part of the metric path, so you can keep a stable
ordering in your dashboards independently of the position of the rule in the chain. The label may
contain letters, digits, spaces, underscores, hyphens and plus signs; spaces are converted to
underscores in the emitted metric name.

### Output format

Two metrics are emitted per tagged rule:

```
<scheme>.iptables.packets.<id>.<name> <count> <timestamp>
<scheme>.iptables.bytes.<id>.<name> <count> <timestamp>
```

For the rules above, on a host checked in as `web01`:

```
web01.iptables.packets.10.http 48123 1757404800
web01.iptables.bytes.10.http 7412998 1757404800
web01.iptables.packets.20.https 991204 1757404800
web01.iptables.bytes.20.https 1044238812 1757404800
web01.iptables.packets.30.ssh_admin 812 1757404800
web01.iptables.bytes.30.ssh_admin 64291 1757404800
```

Note that these are the raw kernel counters, which are cumulative and reset when the rule is
replaced or the ruleset is reloaded. Treat them as counters in your time-series backend
(`nonNegativeDerivative` in Graphite, `rate()` in Prometheus-style tooling).

## Usage examples

### Help output

```
metrics for iptables

Usage:
  metrics-iptables [flags]
  metrics-iptables [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -b, --bin string      location of the firewall binary (default "/usr/sbin/xtables-legacy-multi")
  -f, --ftype string    type of firewall (generally iptables or iptables-nft) (default "iptables")
  -h, --help            help for metrics-iptables
  -s, --scheme string   Scheme to prepend metric

Use "metrics-iptables [command] --help" for more information about a command.
```

### Command line

Legacy iptables (the default):

```
sensu-iptables-metrics --scheme $(hostname -s)
```

nftables backend:

```
sensu-iptables-metrics --scheme $(hostname -s) --bin /usr/sbin/xtables-nft-multi --ftype iptables-nft
```

## Configuration

### Asset registration

[Sensu Assets][10] are the best way to make use of this plugin. If you're not using an asset, please
consider doing so! If you're using sensuctl 5.13 with Sensu Backend 5.13 or later, you can use the
following command to add the asset:

```
sensuctl asset add elfranne/sensu-iptables-metrics
```

If you're using an earlier version of sensuctl, you can find the asset on the
[Bonsai Asset Index](https://bonsai.sensu.io/assets/elfranne/sensu-iptables-metrics).

### Check definition

```yml
---
type: CheckConfig
api_version: core/v2
metadata:
  name: sensu-iptables-metrics
  namespace: default
spec:
  command: sensu-iptables-metrics --scheme {{ .name }}
  subscriptions:
  - system
  runtime_assets:
  - elfranne/sensu-iptables-metrics
  interval: 60
  publish: true
  output_metric_format: graphite_plaintext
  output_metric_handlers:
  - graphite
```

`--scheme` is required; the check exits `WARNING` without it. Using the `{{ .name }}` token
prefixes every metric with the entity name, which is usually what you want.

### Permissions

Reading iptables counters requires `CAP_NET_ADMIN`, so the check normally has to run as root.
The Sensu agent typically already does; if yours does not, grant the capability to the firewall
binary or run the check through `sudo`.

## Installation from source

The preferred way of installing and deploying this plugin is to use it as an Asset. If you would
like to compile and install the plugin from source or contribute to it, download the latest version
or create an executable script from this source.

From the local path of the sensu-iptables-metrics repository:

```
go build
```

Run the tests with:

```
go test ./...
```

## Contributing

For more information about contributing to this plugin, see [Contributing][1].

[1]: https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md
[6]: https://docs.sensu.io/sensu-go/latest/reference/checks/
[10]: https://docs.sensu.io/sensu-go/latest/reference/assets/
[11]: https://graphite.readthedocs.io/en/latest/feeding-carbon.html#the-plaintext-protocol
