# Migration from legacy commands

The refactor intentionally removes public compatibility with `fgt-tools.sh`, direct execution of
`rootfs_decrypt.py`, `build/fortios800.py`, and every host-side build/deployment Shell script.
Extract the complete tool directory and use its `./fortigate-patcher` launcher without installation.

| Legacy command | Current command |
| --- | --- |
| `./fgt-tools.sh list-versions` | `./fortigate-patcher profile list` |
| `./fgt-tools.sh decrypt --version V ...` | `./fortigate-patcher rootfs decrypt --profile V ...` |
| `./fgt-tools.sh build --version V --input-dir D ...` | `./fortigate-patcher image build --profile V --boot-dir D ...` |
| `./fgt-tools.sh verify --version V ...` | `./fortigate-patcher image verify --profile V ...` |
| `./fgt-tools.sh deploy ...` | `sudo ./fortigate-patcher disk plan ...`, review, then `sudo ./fortigate-patcher disk apply ...` |
| `build/qemu-smoke-test.sh ...` | `./fortigate-patcher qemu smoke ...` |
| `build/prepare_decoupled_disk.sh` | included in reviewed `disk plan`/`disk apply` |
| `build/deploy_rootfs.sh` | included in `disk apply` |

Option names changed deliberately:

- `--version` is now `--profile` and accepts an exact profile ID or unambiguous version.
- `--input-dir` is now `--boot-dir`.
- `--force` is now the narrower `--replace` for build/decrypt outputs.
- Deployment no longer combines preflight and write behind an `--apply` flag. A serialized plan is
  mandatory and its canonical device must be repeated as `--confirm-device`.

The old fixed client key, fixed Dropbear host keys, password TTY login, and default Telnet/bind/
reverse listeners have no automatic migration. Create or reuse an environment directory and use
the generated key shown by the command. Unsafe listeners require a new explicit policy with
`unsafe.enabled = true`.

`PATCH_PROFILE.json`, `TEST1_PATCH_PROFILE.json`, and `PATCHED_MANIFEST.sha256` are replaced by the
strict, per-build `BUILD_MANIFEST.json`. Generated rootfs goldens are no longer profile constants;
actual build hashes and the public-key fingerprint are recorded in that manifest and verified
structurally.
