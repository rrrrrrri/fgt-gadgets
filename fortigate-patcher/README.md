# FortiGate Patcher

FortiGate Patcher is a version-aware research toolkit for FortiGate VM firmware. It verifies known
stock images, decrypts FortiOS 8 protected root filesystems, applies research patches, etc. You will get a fully functional FortiGate security research/debugging environment.

The implementation requires Python 3.11 or newer and has no third-party Python package
dependencies. Shell is used only for the small BusyBox scripts that execute inside the FortiOS. The tool currently has profiles for:

- FortiOS 8.0.0 build0167 (ESXi ova)
- FortiOS 8.0.1 build0245 (ESXi ova)

## Requirements

Basic profile inspection, decryption, and image verification need only Python. Other operations
require host commands:

- creating a new build environment: `ssh-keygen`;
- disk planning: `lsblk`, `sfdisk`, `blockdev`, `findmnt`, `mount`, and `umount`;
- disk apply/restore: the planning commands plus `zstd`, `dd`, `blkid`, `e2fsck`, `resize2fs`,
  `mkfs.ext4`, `partprobe`, `udevadm`, `grub-install`, and `sync`;
- optional QEMU testing: `mke2fs` and `qemu-system-x86_64`.

The tool reports a missing command before trying to use it. Install system commands with the host
operating system's package manager.

Long-running commands are quiet by default. Add `--verbose` to `rootfs decrypt`, `image build`,
`image verify`, `disk plan`, `disk apply`, `disk restore`, or `qemu smoke` to display elapsed time,
stage changes, byte-level progress for full-disk operations, and subprocess diagnostics.

## Usage

Clone the repository, keep the
`fortigate-patcher` launcher and `fortigate_patcher/` directory together, and run:

```bash
./fortigate-patcher profile list
```

Python must be version 3.11 or newer.

Inspect a profile:

```consbashole
./fortigate-patcher profile show fortios-8.0.1-build0245
```

Decrypt rootfs:

```bash
./fortigate-patcher rootfs decrypt \
  --profile fortios-8.0.1-build0245 \
  --flatkc /path/to/BOOT/flatkc \
  --rootfs /path/to/BOOT/rootfs.gz \
  --output work/rootfs.plain.gz
```

Build and verify a decoupled image. If no `--environment-dir` is supplied, a UUID-named
environment and Ed25519 client key are created below
`~/.local/share/fortigate-patcher/environments/`.

```bash
./fortigate-patcher image build \
  --profile fortios-8.0.1-build0245 \
  --boot-dir /path/to/mounted/BOOT \
  --output-dir work/image

./fortigate-patcher image verify \
  --profile fortios-8.0.1-build0245 \
  --directory work/image
```

Disk writes use a two-step interface and require root privileges. The `plan` phase mounts the BOOT partition
read-only, hashes the whole disk before and after, builds and verifies artifacts, and writes
`deployment-plan.json`. This is a read-only phase and never writes the target disk.

`disk apply` revalidates the complete disk hash, identity, size, sector size, partition table,
stock files, build manifest, and environment. It creates and verifies a compressed full-disk
backup before the first write. If a later step fails, it attempts a full restore and verifies the
original disk SHA-256.

The `apply` phase will modify the disk so be careful when using this command.

```bash
sudo ./fortigate-patcher disk plan \
  --profile fortios-8.0.1-build0245 \
  --device /dev/sdb \
  --workspace /var/tmp/fortigate-plan \
  --backup-dir /srv/fortigate-backups \
  --environment-dir /srv/fortigate-environments/lab-vm \
  --verbose

sudo ./fortigate-patcher disk apply \
  --plan-file /var/tmp/fortigate-plan/deployment-plan.json \
  --confirm-device /dev/sdb \
  --verbose
```

When a disk command runs through `sudo` without `--environment-dir`, its default environment is
created below root's home directory. Supplying an explicit directory makes the generated client
key easier to locate and preserve.

## Quick Start

Take the FortiGate 8.0.1 build0245 ESXi ova virtual machine as an example. Make sure you have a separate Linux system (SP-SYS) that has the tools installed.

First, complete the installation process and network configuration to ensure that you can access the Web page of FortiGate.

You need to ensure that the network interface has the following configuration:

```
set allowaccess ping https http ssh telnet
```

Shutdown the FortiGate and mount the disk1(2GB disk) onto SP-SYS.

Execute the following command on SP-SYS:

```bash
# Find the disk path, normally /dev/sdb
lsblk

# Plan
sudo ./fortigate-patcher disk plan \
  --profile fortios-8.0.1-build0245 \
  --device /dev/sdb \
  --workspace ./work \
  --backup-dir ./backup \
  --environment-dir ./env \
  --verbose

# Apply
sudo ./fortigate-patcher disk apply \
  --plan-file ./work/deployment-plan.json \
  --confirm-device /dev/sdb \
  --verbose
```

Shutdown SP-SYS and mount the disk1 back to the FortiGate, boot the system.

Execute the following command on SP-SYS to access the Root Shell:

```bash
ssh -i ./env/client_ed25519 root@x.x.x.x -p 23
```

## Documentation

- [Architecture and design](docs/ARCHITECTURE.md)
- [Firmware profile guide](docs/FIRMWARE_PROFILES.md)
- [Operations, backup, recovery, and optional QEMU](docs/OPERATIONS.md)
- [Security model and credential lifecycle](docs/SECURITY.md)
- [Migration from the legacy scripts](docs/MIGRATION.md)
- [Third-party asset provenance](docs/THIRD_PARTY.md)

## Development

If you want to add new features/add new version profile, I suggest that you shoule use an AI model to assist the development.
