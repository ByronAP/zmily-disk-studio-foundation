# Third-party dependencies

This repository distributes ZMILY Foundation source and a Cargo lockfile. It
does not vendor dependency source, distribute compiled binaries or include
Microsoft ADK/WinPE files. Cargo obtains dependencies separately from the
registry. Each dependency retains its own copyright and license; the project's
GPL notice does not replace those terms or claim ownership of dependency code.

The following inventory was read from Cargo metadata for the locked source
snapshot on 2026-09-11. It includes build/dev and target-specific dependencies,
not just code included in a particular binary. Links identify the exact crate
version; consult that crate's packaged license and notice files for its terms.

| Crate | Version | Declared license |
| --- | --- | --- |
| [base64](https://crates.io/crates/base64/0.23.1) | 0.23.1 | MIT OR Apache-2.0 |
| [block-buffer](https://crates.io/crates/block-buffer/0.10.4) | 0.10.4 | MIT OR Apache-2.0 |
| [cfg-if](https://crates.io/crates/cfg-if/1.0.4) | 1.0.4 | MIT OR Apache-2.0 |
| [cpufeatures](https://crates.io/crates/cpufeatures/0.2.17) | 0.2.17 | MIT OR Apache-2.0 |
| [crypto-common](https://crates.io/crates/crypto-common/0.1.7) | 0.1.7 | MIT OR Apache-2.0 |
| [digest](https://crates.io/crates/digest/0.10.7) | 0.10.7 | MIT OR Apache-2.0 |
| [generic-array](https://crates.io/crates/generic-array/0.14.7) | 0.14.7 | MIT |
| [itoa](https://crates.io/crates/itoa/1.0.18) | 1.0.18 | MIT OR Apache-2.0 |
| [libc](https://crates.io/crates/libc/0.2.189) | 0.2.189 | MIT OR Apache-2.0 |
| [md-5](https://crates.io/crates/md-5/0.10.6) | 0.10.6 | MIT OR Apache-2.0 |
| [memchr](https://crates.io/crates/memchr/2.8.3) | 2.8.3 | Unlicense OR MIT |
| [proc-macro2](https://crates.io/crates/proc-macro2/1.0.107) | 1.0.107 | MIT OR Apache-2.0 |
| [quote](https://crates.io/crates/quote/1.0.47) | 1.0.47 | MIT OR Apache-2.0 |
| [serde](https://crates.io/crates/serde/1.0.229) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_core](https://crates.io/crates/serde_core/1.0.229) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_derive](https://crates.io/crates/serde_derive/1.0.229) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_json](https://crates.io/crates/serde_json/1.0.151) | 1.0.151 | MIT OR Apache-2.0 |
| [sha1](https://crates.io/crates/sha1/0.10.6) | 0.10.6 | MIT OR Apache-2.0 |
| [sha2](https://crates.io/crates/sha2/0.10.9) | 0.10.9 | MIT OR Apache-2.0 |
| [syn](https://crates.io/crates/syn/3.0.3) | 3.0.3 | MIT OR Apache-2.0 |
| [thiserror](https://crates.io/crates/thiserror/2.0.20) | 2.0.20 | MIT OR Apache-2.0 |
| [thiserror-impl](https://crates.io/crates/thiserror-impl/2.0.20) | 2.0.20 | MIT OR Apache-2.0 |
| [typenum](https://crates.io/crates/typenum/1.20.0) | 1.20.0 | MIT OR Apache-2.0 |
| [unicode-ident](https://crates.io/crates/unicode-ident/1.0.24) | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| [version_check](https://crates.io/crates/version_check/0.9.5) | 0.9.5 | MIT/Apache-2.0 (as declared upstream) |
| [zmij](https://crates.io/crates/zmij/1.0.23) | 1.0.23 | MIT |

Before distributing binaries or vendored dependencies, collect and distribute
all applicable upstream copyright, license and notice texts for that artifact.
This inventory is not a substitute for those notices or a claim that future
dependencies have been reviewed.
