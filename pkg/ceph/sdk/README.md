# Ceph SDK Integration

This package provides optional Ceph SDK integration using native RADOS API.

## Build Requirements

The SDK integration requires:
- Linux operating system
- CGO enabled
- librados2 and librados-dev installed

## Build Tags

The SDK code is conditionally compiled using build tags:
- `ceph_sdk`: Enable SDK integration (requires CGO and librados)
- Without this tag: Falls back to shell-based diagnostics only

## Usage

To build with SDK support on Linux:
```bash
go build -tags ceph_sdk -o eos ./cmd/
```

To build without SDK (works on Mac/Windows):
```bash
go build -o eos ./cmd/
```

## Implementation

The diagnostics will automatically detect if SDK is available at runtime and use it for:
- Faster cluster connectivity checks (native RADOS API)
- Direct monitor quorum queries
- Real-time cluster health statistics

If SDK is not available, it gracefully falls back to shell commands.
