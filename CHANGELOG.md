# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- CI now runs `go vet`, builds, and runs the tests with `-race` plus a coverage summary.
- Workflows declare least-privilege `permissions` and cancel superseded runs via a
  `concurrency` group. Test and lint also run on `pull_request` and `workflow_dispatch`.
- Real test coverage for the rule parser: a table-driven `main_test.go` built on captured
  `iptables -L -nvx` output, covering chain and column headers, untagged rules, extra match
  extensions, digit-heavy addresses, `uint64` counters, and the documented quirks of the
  comment regex.

### Changed
- `.goreleaser.yml` migrated to the GoReleaser v2 schema: added `version: 2`, replaced the
  deprecated `archives.format` with `formats`, and dropped `goos`/`goarch`, which GoReleaser
  ignores when `targets` is set. The previous file failed `goreleaser check`. Archive filenames
  are unchanged.
- The release workflow checks out with `fetch-depth: 0` instead of running
  `git fetch --prune --unshallow`, which errors when the checkout is already complete. It also
  runs the tests before releasing.
- Pinned `golangci-lint` to v2.13 so a lint release cannot break CI unannounced.
- The test workflow no longer runs on macOS and Windows; the plugin is Linux-only.
- Extracted parsing and metric formatting out of `executeCheck` into `writeMetrics`, so it can
  be tested without shelling out to iptables. Metric output is unchanged.
- The rule regex is compiled once at package level instead of on every invocation.

### Fixed
- `.bonsai.yml` now declares the `linux_armv5` build. GoReleaser has been building that archive
  all along, but Bonsai never referenced it, so armv5 entities could not resolve the asset.
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
