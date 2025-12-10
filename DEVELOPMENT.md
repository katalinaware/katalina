# Development Guide

This document contains information for developers and maintainers of katalinaware.

## Version Upgrades

### Golang Version Upgrades

When you upgrade the Go version in `go.mod`, make sure to also update the version in `.github/workflows/build.yaml` in the CI configuration.

The CI workflow uses the Go version specified in the matrix:

```yaml
strategy:
  matrix:
    go-version: [1.24]  # Update this when upgrading go.mod
```

## Releases

To create releases you need `gox`. You can follow the installation instructions on their [github page](https://github.com/mitchellh/gox). For macOS, you can also install `gox` from [homebrew](https://formulae.brew.sh/formula/gox):

```bash
brew install gox
```

Change directory into the katalinaware code repo:

```bash
cd katalinaware
```

Run the below `gox` command within the `katalinaware` repo:

```bash
gox -osarch="darwin/amd64 darwin/arm64 linux/386 linux/amd64 windows/amd64" -output="katalinaware1.0.0_{{.OS}}_{{.Arch}}"
```

When built on macOS using only `-osarch=darwin/arm64` the above produces the name `katalinaware1.0.0_darwin_arm64`. The versioning `1.0.0` follows [semantic versioning](https://semver.org/)'s `MAJOR.MINOR.PATCH`.

## Semantic Versioning and Commit Messages

We use semantic versioning to manage releases of this project. It is crucial to follow the semantic versioning rules for maintaining consistency and predictability in version management. To automate the versioning and release process, our Continuous Deployment (CD) pipeline is configured to bump version numbers based on commit messages.

When committing changes, include one of the following tags in your commit message to indicate the nature of the change and to trigger the appropriate version bump:

- `#major`: Use for significant changes or breaking changes. This will increment the major version number (e.g., 1.0.0 to 2.0.0).
- `#minor`: Use for backward-compatible feature additions. This will increment the minor version number (e.g., 1.0.0 to 1.1.0).
- `#patch`: Use for backward-compatible bug fixes. This will increment the patch version number (e.g., 1.0.0 to 1.0.1).

Example commit message: `Fix issue with user login #patch`

## Code Formatting

You can use [`vscode-clang-format`](https://github.com/xaverh/vscode-clang-format) as the formatter. This requires installing `clang` formatter. For a macOS dev environment, that will be:

```bash
brew install clang-format
```

## Profiling and Performance Analysis

The katalinaware tool includes built-in support for Go's profiling and tracing capabilities to help analyze performance and debug issues.

### Execution Tracing

To capture execution traces for performance analysis, use the `--trace` flag:

```bash
go run . --file '.\thief_quest\ae1ce10ec65b2c356fae5119dea0b01bb3d51e80bff444b4254b62db6ce3a51d (1)' --output_dir output_dir --max_concurrency 0 --trace=trace.out
```

You can then analyze the trace file using Go's trace tool:

```bash
go tool trace trace.out
```

### CPU Profiling

For CPU profiling, use the `--cpuprofile` flag:

```bash
go run . --input_dir ./samples/ --output_dir output_dir --cpuprofile=cpu.prof
```

Analyze the CPU profile:

```bash
go tool pprof cpu.prof
```

### Memory Profiling

For memory profiling, use the `--memprofile` flag:

```bash
go run . --input_dir ./samples/ --output_dir output_dir --memprofile=mem.prof
```

Analyze the memory profile:

```bash
go tool pprof mem.prof
```

### Live Profiling Server

Enable the pprof HTTP server for live profiling during execution:

```bash
go run . --input_dir ./samples/ --output_dir output_dir --profile
```

Then access the profiling interface at `http://localhost:6060/debug/pprof/` while the tool is running.

## Development Prerequisites

### Protocol Buffers

This project uses Protocol Buffers for its output schema. To regenerate the Go types:

Install protoc (example for macOS):

```bash
brew install protobuf
```

Install the Go plugin:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

Generate code:

```bash
protoc --go_out=. --go_opt=paths=source_relative protos/katalinaware.proto
```

### Windows protoc helper (if needed)

If your protoc command is not working on Windows, try the following batch script:

```bash
@echo off
echo Installing protoc-gen-go...
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

echo.
echo Adding Go bin to PATH for this session...
set PATH=%PATH%;%USERPROFILE%\go\bin

echo.
echo Verifying installation...
where protoc-gen-go
protoc-gen-go --version

echo.
echo Running protoc command...
protoc --go_out=. --go_opt=paths=source_relative protos/katalinaware.proto

echo.
echo Done! To make PATH permanent, add %USERPROFILE%\go\bin to your system PATH.
pause
```

## Development Notes (7-Zip)

The tool embeds 7-Zip command-line binaries for supported platforms and uses them internally to inspect and extract archives. If you want to experiment with 7-Zip manually:

### Windows

```bash
.\7z.exe e Absolute\Path\To\Object -oAbsolute\Path\To\Destination\ -y
```

### macOS

We have downloaded the `tar.xz | macOS (arm64 / x86-64) | 7-Zip for MacOS: console version` from the [7-zip](https://www.7-zip.org/download.html) website.

We extracted the archive and retrieved the macho `7zz` file. The README files are also attached to the folder.

We proceed to remove the Quarantine bit since it was downloaded from internet:

```bash
ls -l@ ~/Downloads/7zz # To view the quarantine bit.
xattr -d com.apple.quarantine ~/Downloads/7zz # remove the quarantine bit.
```

Example usage: `7zz l example_image.dmg -slt`
