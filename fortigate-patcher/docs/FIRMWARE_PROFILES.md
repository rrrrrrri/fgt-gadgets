# Firmware profile guide

Profiles are data-only TOML resources in `fortigate_patcher/profiles/`. The current schema version
is 1. File names should be the exact profile ID plus `.toml`.

## Schema

Top-level fields identify the build and select generic strategies:

```toml
schema_version = 1
profile_id = "fortios-8.0.1-build0245"
fortios_version = "8.0.1"
build = "0245"
firmware_adapter = "fortios-v8-vm64"
manifest_strategy = "filechecksum" # or "db"
```

`rootfs_envelope` records the adapter and kernel virtual addresses for the encoded public key.
`cipher` selects a registered transform and its data parameters. `outputs` defines names that must
not collide with stock files. `grub.kernel_args` is used verbatim after TOML and profile validation.

`stock.files` is the complete copy whitelist and SHA-256 set. It must include `flatkc` and
`rootfs.gz`. No undeclared file is copied into a build.

`invariants.original` and `invariants.patched` contain stable binary goldens. The invariant table
also includes `patched_kernel_sha256` and `patched_flatkc_sha256`. Generated rootfs hashes do not
belong here because environment public keys and policy are build inputs.

Patches use repeated tables:

```toml
[[userland_patches]]
target = "sbin/init"
label = "early init handoff"
offset = 0x1b6c
expected = "2f62696e2f696e697400"
replacement = "2f62696e2f77696e6900"

[[kernel_patches]]
label = "P2_initrd_integrity"
offset = 0x19117cb
expected = "74"
replacement = "eb"
```

Offsets are file offsets in the selected target. Expected and replacement values are hexadecimal
and must have equal non-zero length. Patch ranges for one target may not overlap.

## Adding a build that uses existing formats

1. Copy a nearby profile and give it a unique exact ID.
2. Record a complete stock whitelist from trusted original media.
3. Select the existing manifest, rootfs-envelope, firmware, and cipher strategies.
4. Locate each patch independently and record its original bytes.
5. Produce the patched per-binary, kernel ELF, and flatkc golden hashes.
6. Validate profile loading, cipher vectors, original-byte rejection, and golden hashes.
7. Build twice with the same environment and policy and compare every output byte.
8. Perform static verification and an authorized isolated boot test.

Never reuse a short version selector when multiple builds share that version; the registry will
make the short selector ambiguous and require the exact profile ID.

## Adding a genuinely new format

Add one typed adapter and register its stable name. Keep version detection and addresses in TOML.
Examples of adapter boundaries are the protected-rootfs envelope, stock-manifest validation,
cipher construction, and firmware kernel container. Do not fork the application build workflow.
