# ZMILY Disk Studio Foundation

Reusable Rust storage and file-format primitives shared with ZMILY Disk Studio.
This source tree contains the foundation library, not a complete partition
manager or the commercial product's Free edition.

The library provides filesystem signature detection and GPT/MBR type
classification, checked byte/sector size parsing, bounded recovery previews and
LZNT1 decoding, ISO/UDF/El Torito parsing, streaming checksums, PE inspection and
bounded file reads. Image parsers operate on reads supplied by the caller.

It contains no Windows storage API dependency, partition executor,
clone/wipe/sanitize workflow, damaged-drive imager, WinPE orchestration, product
entitlement enforcement, CLI or desktop application. Generic file reads use
caller-supplied paths; product path admission remains the caller's responsibility.

## Build and test

Install Rust using the pinned `rust-toolchain.toml`, then run:

```text
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

The `test-fixtures` feature exposes a synthetic ISO fixture for consumer tests;
it does not add product functionality. Tests use buffers and temporary files,
with no physical storage access.

The private product consumes this same library. Shared contributions are
reviewed and integrated there, then included in subsequent source snapshots.

The public repository is [ZMILY Disk Studio Foundation](https://github.com/ByronAP/zmily-disk-studio-foundation).

## Publication status

The project was previously named ZMILY Foundation. The version 1.0 [CLA](CLA.md)
retains that name and explicitly includes renamed continuations.

The public source is licensed under **GPL-3.0-only**; see [LICENSE](LICENSE)
and [LICENSING.md](LICENSING.md) for scope and separate proprietary licensing.
Allen Byron Penner is the initial project steward. Contributions retain their
respective owners' copyrights.

This repository publishes the independently buildable foundation source, not
product binaries or private product history. See [third-party dependency
information](THIRD_PARTY.md). The one-time [CLA](CLA.md), version 1.0, is approved
by the project owner and open for maintainer-verified acceptance. Contributors
must complete the [private signing process](CONTRIBUTING.md) before merging;
owner approval does not sign the agreement for anyone else or represent
independent legal review.
