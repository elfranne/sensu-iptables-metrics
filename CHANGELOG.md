# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed
- `.goreleaser.yml` migrated to the GoReleaser v2 schema: added `version: 2`, replaced the
  deprecated `archives.format` with `formats`, and dropped `goos`/`goarch`, which GoReleaser
  ignores when `targets` is set. The previous file failed `goreleaser check`. Archive filenames
  are unchanged.

### Fixed
- `.bonsai.yml` now declares the `linux_armv5` build. GoReleaser has been building that archive
  all along, but Bonsai never referenced it, so armv5 entities could not resolve the asset.

## [0.0.1] - 2000-01-01

### Added
- Initial release
