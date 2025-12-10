# katalinaware

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org)
[![Build&Release](https://github.com/appsworld/katalinaware/workflows/Build%26Release/badge.svg)](https://github.com/appsworld/katalinaware/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/appsworld/katalinaware)](https://goreportcard.com/report/github.com/appsworld/katalinaware)

## Overview

Katalinaware analyzes macOS Mach-O binaries, including those embedded inside common archive formats, and produces a JSON report of rich binary features. The tool includes advanced path validation and security analysis capabilities:

- **Enhanced Path Validation**: Filters out programming artifacts and invalid filesystem paths
- **Format String Detection**: Identifies dynamic path construction patterns for security analysis
- **Plist Path Validation**: Validates property list file paths to ensure accuracy
- **Control Flow Graph Generation**: Advanced CFG analysis for code structure understanding
- **Comprehensive Binary Analysis**: Extracts strings, symbols, certificates, and structural features

## Installation

The easiest way to get started is to download a prebuilt binary from the project's releases:

- Download the latest binary for your OS/architecture from the [Releases](https://github.com/katalinaware/katalinaware/releases) page
- On macOS and Linux, make it executable if needed:

```bash
chmod +x katalinaware
```

- Optional (macOS): if the file is quarantined by Gatekeeper, remove the bit:

```bash
xattr -d com.apple.quarantine ./katalinaware
```

## Quick start

Analyze a single Mach-O file:

```bash
./katalinaware --file /path/to/app/Contents/MacOS/AppBinary
```

Analyze all samples in a directory (each subfolder is treated as a sample):

```bash
./katalinaware --input_dir /path/to/samples
```

Specify a custom output directory:

```bash
./katalinaware --file /path/to/binary --output_dir /path/to/output
```

Analyze with all strings and symbols:

```bash
./katalinaware --file /path/to/binary --all_strings --all_symbols
```

Generate Control Flow Graph (for advanced analysis):

```bash
./katalinaware --file /path/to/binary --generate_cfg
```

The output JSON will be written to the specified output directory (or current working directory if not specified).

## Usage

### Basic Options
- `--file <path>`: analyze a single Mach-O binary
- `--input_dir <dir>`: analyze a directory containing sample folders
- `--output_dir <dir>`: specify output directory for JSON reports (default: current directory)

### Analysis Options
- `--all_strings`: return all strings found in the binary (not just filtered ones)
- `--all_symbols`: include all binary symbols in the analysis
- `--generate_cfg`: generate Control Flow Graphs (expensive operation, significantly impacts performance)

### Processing Options
- `--skip_parsed`: skip directories that already have result files
- `--debug`: turn on debug mode and attach debug server on port 8801

## Logs

All errors, warnings, and informational messages are written to a log file in the system's temporary directory (e.g., `/var/folders/.../katalinaware.log` on macOS). The exact location is displayed when the tool starts. This file is ignored by version control.

## Building from source

Katalinaware is written in Go. Use a Go toolchain compatible with the version declared in `go.mod` (the `go` directive).

- If your installed `go` already meets or exceeds that version, use the standard commands:

```bash
go build
# or
go run . --file /path/to/binary
```

- If your local `go` is older, either install a matching Go version from the official downloads, or use a local shim that matches the version in `go.mod` without hardcoding it:

```bash
# Extract the version from go.mod (e.g., 1.24) and form a shim name (e.g., go1.24.0)
GO_MOD_VERSION=$(awk '/^go [0-9]+\.[0-9]+/{print $2}' go.mod)
GO_SHIM="go${GO_MOD_VERSION}.0"

# Install and download the toolchain shim
go install "golang.org/dl/${GO_SHIM}@latest"
"$HOME/go/bin/${GO_SHIM}" download

# Optional for convenience
export PATH="$HOME/go/bin:$PATH"

# Build/run with the shim
"${GO_SHIM}" build
"${GO_SHIM}" run . --file /path/to/binary
```

Note that running `go build` will also download the dependencies specified in `go.mod`.

## Releases

Prebuilt binaries for Windows, macOS, and Linux are available on the [Releases](https://github.com/katalinaware/katalinaware/releases) page.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request. Please keep commit messages clear and consider semantic versioning in PRs when appropriate (e.g., `#patch`, `#minor`, `#major`).

## For Developers

If you're contributing to the project, see [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development setup, release procedures, and internal documentation.
