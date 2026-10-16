# Architecture and design

## Goals

The design separates stable workflow code from version-specific data. Adding a firmware build that
uses the existing FortiOS 8 formats requires one TOML profile, not another build script. New binary
formats are introduced as named adapters and registered once in the generic firmware layer.

The source tree:

```text
├──application/  use cases: decrypt, build, verify, disk, QEMU
├── domain/  immutable profiles, policies, manifests, plans, errors
├── firmware/ pure parsing, crypto, archive, patch, and validation code
└── platform/ subprocess, disks, mounts, credentials, GRUB, QEMU

profiles/*.toml       version data only
resources/binaries/   pinned third-party assets
resources/guest/      scripts that run inside BusyBox/FortiOS only
```

The root launcher imports the adjacent `fortigate_patcher/` package directly. Profiles and assets
are loaded through `importlib.resources`, so resource access is independent of the caller's current
working directory.

## Build data flow

```text
verified stock BOOT ──┬── flatkc ── gzip kernel ELF ── guarded patches ── flatkc_p
                     │
                     └── rootfs.gz ── RSA trailer ── stream decrypt ── gzip/newc
                                                           │
 environment public key + policy ── guest payload ── bin.tar.xz/newc patches
                                                           │
                                                           └── stream encrypt
                                                                 └── rootfs_p.gz

flatkc_p + rootfs_p.gz + stock files + GRUB + debugger runtime
                              └── BUILD_MANIFEST.json ── full static verification
```

The FortiOS scanner continues to see the original
`flatkc`, `rootfs.gz`, signatures, checksums, and libraries. GRUB loads `flatkc_p` from partition 1
and `rootfs_p.gz` from the separate `FGT_PATCH` partition 4.

## Protected rootfs container

The kernel ELF contains an XOR-obfuscated 2048-bit RSA public key. The selected profile supplies
the virtual addresses and lengths of the DER blob and XOR mask. `Elf64Image` maps these virtual
addresses only through file-backed `PT_LOAD` segments.

The protected rootfs consists of a fixed-size encrypted payload followed by a 256-byte raw RSA
trailer. The decoded trailer has PKCS#1-style `00 01 FF...00` padding, the encrypted-payload
SHA-256, an auxiliary 32-byte field, and a 32-byte stream key. Stock decryption requires the signed
digest to match. Patched-rootfs verification deliberately permits the preserved stock signature to
have a different digest, but still validates its padding and uses the signed stream key.

Both supported builds use the registered `fortios-v8-stream` transform. Their KSA carry behavior
and index shifts differ and live in TOML. The same stateful cipher class handles one-shot builds and
streaming known-answer tests.

## Patch model

Every patch has a label, target, offset, original bytes, and same-length replacement bytes. A patch
is applied only when the original bytes match exactly. Already-patched bytes are accepted for
idempotent low-level use; all other values fail closed. Profile loading rejects empty, overlapping,
negative, or length-changing patches before any firmware is read.

Stable golden SHA-256 values cover:

- every version-specific input binary that is patched;
- every resulting patched binary;
- the decompressed patched kernel ELF; and
- the recompressed `flatkc_p` container.

The generated rootfs intentionally has no fixed golden hash because its authorized key and policy
are environment-specific. It is verified structurally: newc and TAR integrity, expected patch
bytes, patched-binary goldens, account modes, exact rendered payload, safe policy behavior, public
key fingerprint, and absence of private-key material. Its actual gzip, CPIO, and payload hashes are
recorded in the per-build manifest.

## Determinism

Gzip output uses timestamp zero and a normalized OS byte. New newc and TAR members have stable
ownership, modes, order, and timestamps. JSON is sorted and has no wall-clock field. Rebuilding the
same stock files with the same environment directory and policy produces the same firmware
artifacts and `BUILD_MANIFEST.json`.

## Deployment safety boundary

`disk plan` and `disk apply` are intentionally separate. A plan records the canonical device path,
major/minor identity, size, logical sector size, model, serial, WWN, complete-disk SHA-256,
partition-table SHA-256, partition geometry/filesystems/labels, stock fingerprints, build-manifest
hash, environment identity, paths, calculated layout, and intended operations.

Apply requires an explicit `--confirm-device`, recalculates every recorded value, and rejects any
difference. It saves `sfdisk`, `blkid`, the first 4 MiB, and a verified complete zstd image before
the first target write. Mount contexts always unmount on exceptions. Any failure after a possible
write invokes full-image recovery and compares the restored disk with its original SHA-256.
