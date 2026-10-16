# Third-party assets

The following binary assets are bundled under `fortigate_patcher/resources/binaries/`. Runtime
loading verifies these exact SHA-256 values before use.

| Asset | Version/source description | SHA-256 | License/provenance |
| --- | --- | --- | --- |
| `busybox` | BusyBox 1.35.0, static x86-64 build | `6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348` | BusyBox is GPL-2.0-only; source and license: <https://busybox.net/downloads/> |
| `dropbearmulti` | Dropbear 2024.86, static x86-64 multi-call build | `3694a76d5a4ecc7fb67e277342a5385be480b282c6389ecdabf8f6e26264f7e2` | MIT-style Dropbear license; source and license: <https://matt.ucc.asn.au/dropbear/dropbear.html> |
| `gdb-runtime.tar.xz` | self-contained GNU GDB/GDBServer runtime for x86-64, including Python 3.12 runtime dependencies | `b706f527a529963aef42da46932d97b9189c41c2565b56804718783d70fd0b45` | Component licenses and package provenance are embedded below `fortigdb/licenses/` and in `fortigdb/MANIFEST.json` |

The debugger runtime's `gdbserver.real` includes the documented
`fortios-4.19-x86-debug-register-eperm` compatibility patch at file offset `0x52690`, replacing
eight bytes with `41833c2402733290`. Both the binary bytes and embedded manifest record are checked.

The release archive omits Python bytecode caches because their code metadata retained paths from
the runtime build host. Python sources remain available, and the embedded manifest records this
sanitization. Distribution cryptographic libraries may contain their upstream public self-test
fixtures and parser literals; these are package data, not generated or environment credentials.

FortiOS firmware is not included in this repository. Users must supply authorized stock media.
Fortinet product names and firmware are the property of their respective owner. The profile hashes
are interoperability metadata and do not contain firmware bytes.

When replacing a third-party asset:

1. obtain it from its documented upstream or a reproducible internal build;
2. preserve corresponding source/license obligations outside this binary-only research bundle;
3. update this document and the compiled resource hash;
4. perform structural validation appropriate to the asset; and
5. regenerate `SHA256SUMS`.
