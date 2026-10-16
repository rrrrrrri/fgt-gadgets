# Operations guide

Run all examples from the extracted tool directory. No package installation, virtual environment,
or `PYTHONPATH` setting is required. The launcher may also be replaced with its absolute path when
running from another directory.

## Host requirements

Python 3.11 or newer is the only Python dependency. The following non-Python commands are required
only by the operations that use them:

| Operation | Required host commands |
| --- | --- |
| Profile inspection, rootfs decryption, image verification | none beyond Python |
| New environment or image build | `ssh-keygen` |
| Disk plan | `lsblk`, `sfdisk`, `blockdev`, `findmnt`, `mount`, `umount`, `ssh-keygen` |
| Disk apply or restore | the disk-plan commands plus `zstd`, `dd`, `blkid`, `e2fsck`, `resize2fs`, `mkfs.ext4`, `partprobe`, `udevadm`, `grub-install`, `sync` |
| Optional QEMU smoke test | `mke2fs`, `qemu-system-x86_64` |

Install these commands with the host operating system's package manager. They do not belong in
`requirements.txt`, which intentionally contains no third-party Python packages.

## Progress and diagnostics

Long-running operations remain quiet by default. Pass `--verbose` to `rootfs decrypt`, `image
build`, `image verify`, `disk plan`, `disk apply`, `disk restore`, or `qemu smoke` to show:

- elapsed time and the current application stage;
- byte counts and percentages for complete-disk hashing, backup, and restore verification;
- each external command, its exit status, and elapsed time; and
- explicit backup, partitioning, deployment, recovery, and QEMU heartbeat messages.

Verbose output is flushed to stderr. Existing result output remains on stdout, so scripts may
redirect the two streams independently. The option may be placed after the leaf command's
arguments, as in the examples below, or before the top-level command:
`./fortigate-patcher --verbose ...`. Command stdin and credential contents are never included in
diagnostics.

## Build inputs

Mount or copy the FortiOS BOOT filesystem to a directory. The selected profile validates every
whitelisted file and the stock `.db` or `filechecksum` manifest before decrypting firmware.

```console
./fortigate-patcher image build \
  --profile fortios-8.0.1-build0245 \
  --boot-dir /mnt/fortios-boot \
  --output-dir /var/tmp/fortigate-build \
  --policy examples/safe-policy.toml \
  --environment-dir /srv/fortigate-environments/lab-vm \
  --verbose
```

Use `--environment-dir` to reuse an existing target identity. Reuse is what makes repeated builds
deterministic and preserves the client key. If it is omitted, a UUID-named environment is created
below `~/.local/share/fortigate-patcher/environments/`. `--replace` atomically replaces an existing
output only after the staged replacement passes full verification.

The build keeps stock files unchanged and adds `flatkc_p`, `rootfs_p.gz`,
`boot/grub/grub.cfg`, the pinned debugger runtime when enabled, and `BUILD_MANIFEST.json`.

## Verify

```console
./fortigate-patcher image verify \
  --profile fortios-8.0.1-build0245 \
  --directory /var/tmp/fortigate-build \
  --verbose
```

Verification requires the exact manifest file set, checks every byte count and SHA-256, reruns the
stock-manifest strategy, verifies kernel and userland goldens, decrypts the generated rootfs,
reconstructs its expected policy payload, rejects private keys, checks the public-key fingerprint,
validates the debugger archive, and checks the exact GRUB configuration.

## Disk plan

All disk subcommands require root and refuse to invoke `sudo` themselves. The target must be a
whole, writable, unmounted MBR disk with partition 1 labeled `FORTIOS` as ext3, partition 2 as ext3,
and partition 3 after the available data area. Work, environment, and backup paths must not reside
on the target disk or its running root filesystem.

```console
sudo ./fortigate-patcher disk plan \
  --profile fortios-8.0.1-build0245 \
  --device /dev/sdb \
  --workspace /home/lab/fortios/plan-001 \
  --backup-dir /home/lab/fortios/backups \
  --environment-dir /home/lab/fortios/environments/lab-vm \
  --policy examples/safe-policy.toml \
  --verbose
```

When invoked through `sudo`, an omitted environment path defaults below root's home directory,
not the invoking user's home. An explicit path is recommended so the printed SSH private key can
be located and backed up deliberately.

Planning can take time because it reads and hashes the complete disk twice. Partition 1 is mounted
read-only with journal replay disabled (`ro,noload`) only long enough to build, so even a dirty
ext3 journal cannot mutate the target during preflight. The plan is written after the second disk
hash and after the mount is gone. Review `deployment-plan.json`, especially `device`, `layout`,
`paths`, and `operations`, before apply.

## Disk apply

```console
sudo ./fortigate-patcher disk apply \
  --plan-file /home/lab/fortios/plan-001/deployment-plan.json \
  --confirm-device /dev/sdb \
  --verbose
```

Apply reads the whole disk again and rejects any stale field. It then saves:

- the reviewed deployment plan;
- `sfdisk` output;
- targeted `blkid` output;
- the first 4 MiB;
- a complete zstd disk image and its sidecar hashes; and
- a deployment report with public fingerprints.

The backup is accepted only after its decompressed byte count and SHA-256 match the validated
source disk; restore repeats that check before opening the target for writing.

If necessary, partition 2 is checked and shrunk, then partition 4 is created as a 256 MiB ext4
filesystem labeled `FGT_PATCH`. The tool copies `flatkc_p` to partition 1 and `rootfs_p.gz`, the
expanded debugger runtime, and environment-specific Dropbear host identity to partition 4. GRUB is
installed to the whole disk. Every deployed file is compared by size and SHA-256, and the original
stock whitelist is checked again.

On a post-write exception, mounts unwind first, the complete disk image is restored, and the
original disk SHA-256 is checked. Preserve the error and backup directory for diagnosis.

## Manual recovery

```console
sudo ./fortigate-patcher disk restore \
  --backup /home/lab/fortios/backups/PLAN_ID/sdb.img.zst \
  --device /dev/sdb \
  --confirm-device /dev/sdb \
  --verbose
```

Backup reads a block device in Python and streams it to zstd through a subprocess stdin, so zstd is
never asked to open a special file directly. Restore requires the sidecar JSON, verifies the
compressed hash and target size, streams the image without a shell pipeline, flushes it, and
verifies the resulting whole-disk SHA-256.

## Manual boot acceptance

After a successful apply, preserve the plan, build manifest, deployment report, environment
directory, full-disk backup, and boot logs. Attach the disk to the authorized isolated VM and check:

1. GRUB loads `flatkc_p` and `rootfs_p.gz` from the intended partitions.
2. `/init` starts without an integrity failure or kernel panic.
3. The serial output reaches `FGT_PATCHER_ACCOUNT_READY`, `FGT_PATCHER_SSH_READY`, and
   `FGT_PATCHER_READY` for the expected environment UUID.
4. SSH succeeds with the exact client private key printed by the build/plan/apply command.
5. Password authentication fails and the Dropbear host-key fingerprint matches the deployment
   report and remains stable across reboots.
6. Unsafe Telnet, bind-shell, and reverse-shell services remain absent unless the reviewed policy
   explicitly enabled them.
7. GDB and GDBServer can start and operate against a controlled test process when enabled.

If any post-write validation fails, shut down the VM, detach and unmount the disk, restore the full
image, and confirm the restored whole-disk SHA-256 before further investigation.

## Optional QEMU smoke test

The direct-kernel smoke test creates isolated generated files and never writes the source build:

```console
./fortigate-patcher qemu smoke \
  --build-dir /var/tmp/fortigate-build \
  --work-dir /var/tmp/fortigate-qemu \
  --verbose
```

It requires `mke2fs` and `qemu-system-x86_64`, boots `flatkc_p` with `rootfs_p.gz`, and fails unless
the kernel reaches `/init` without an integrity error or panic. This check is optional and does not
replace booting the deployed disk in its intended isolated VM.
