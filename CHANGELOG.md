# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Real test coverage for the rule parser: a table-driven `main_test.go` built on captured
  `iptables -L -nvx` output, covering chain and column headers, untagged rules, extra match
  extensions, digit-heavy addresses, `uint64` counters, and the documented quirks of the
  comment regex.

### Changed
- Extracted parsing and metric formatting out of `executeCheck` into `writeMetrics`, so it can
  be tested without shelling out to iptables. Metric output is unchanged.
- The rule regex is compiled once at package level instead of on every invocation.

### Fixed
- **Behaviour change:** an iptables failure now returns `CRITICAL` with the command's output in
  the error. It previously called `log.Fatalf`, which bypassed the Sensu SDK and exited 1, so
  the check surfaced as `WARNING`. Alerting tuned to WARNING on this check will see a different
  severity.
- All metrics from one run now share a single timestamp. `time.Now()` was called twice per rule,
  so a scrape crossing a second boundary emitted inconsistent timestamps.
- Scanner errors are no longer swallowed; truncated iptables output previously reported `OK`.

## [0.0.1] - 2000-01-01

### Added
- Initial release
