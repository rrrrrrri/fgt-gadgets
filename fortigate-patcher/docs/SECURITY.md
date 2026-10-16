# Security model

## Trust boundaries

The selected firmware profile is a strict allowlist, not a hint. Stock hashes, embedded manifests,
original patch bytes, patched binary goldens, kernel goldens, packaged asset hashes, build manifests,
deployment plans, and deployed bytes are separate checks. A failure at any boundary stops the
workflow.

The pinned BusyBox, Dropbear, and debugger archives are executable third-party inputs. Their hashes
are compiled into the tool, their provenance is documented, and the debugger archive receives
additional structure and compatibility-patch checks. Replacing an asset requires an intentional
code and provenance update.

Disk paths are a privileged boundary. Disk commands require direct root execution, reject the
running root disk, reject work or backup paths hosted by the target, require unmounted partitions,
and never call `sudo`. Plan/apply separation prevents a changed or mistyped device from inheriting
earlier validation.

## Credential lifecycle

Each target environment has a UUID directory, normally:

```text
~/.local/share/fortigate-patcher/environments/<uuid>/
```

Creation uses the host `ssh-keygen` to generate a unique Ed25519 client key. The directory is mode
0700, its client private key is mode 0600, and only the public key is injected into rootfs. The
build manifest records only the environment UUID and OpenSSH SHA-256 public fingerprint.

During Linux disk deployment, the pinned static `dropbearmulti dropbearkey` implementation creates
unique RSA-2048 and Ed25519 host keys. Their private files remain in the environment directory and
are copied with mode 0600 to `FGT_PATCH/identity/`. They are never stored in rootfs, the build tree,
the build manifest, the deployment plan, the distributed source directory, or logs. Public host
fingerprints are added to the environment and deployment reports.

The exact SSH command is printed after build/plan/apply. Protect and back up the environment
directory separately; losing it loses both client authentication and the reference host identity.

## Default guest policy

The default policy is intentionally narrow:

- key-only Dropbear SSH on TCP port 23;
- password authentication disabled (`-s`) and root password authentication disabled (`-g`);
- locked root password (`!` in shadow);
- no interactive TTY root login;
- GDB and GDBServer binaries available through the verified read-only runtime;
- no Telnet shell;
- no bind shell;
- no reverse shell; and
- no automatic DHCP request unless explicitly enabled for an acceptance environment.

The QEMU acceptance-only policy enables DHCP with `network.interface = "auto"`, which selects the
first non-loopback kernel interface. DHCP remains disabled in the safe default policy.

FortiOS mounts its persistent filesystem at `/data` after the initramfs starts, while `/etc` is a
symlink to `/data/etc`. The guest bootstrap therefore waits for that mount before installing the
locked root account and authorized key. It emits `FGT_PATCHER_ACCOUNT_READY data=/data` only after
the late account overlay succeeds; Dropbear is not started if the overlay fails.

The bootstrap reads host keys from the separate read-only patch partition and emits
`FGT_PATCHER_SSH_READY port=<port>` only after daemonized Dropbear has created its PID file and is
still alive. It then emits `FGT_PATCHER_READY environment=<uuid>` after startup processing. A failed
account overlay or daemon launch produces `FGT_PATCHER_SSH_FAILED` and a status instead of silently
hiding the failure.

## Unsafe features

Legacy listeners are retained only for isolated research compatibility. Each requested listener
also requires the master switch:

```toml
[unsafe]
enabled = true
telnet_shell = true
bind_shell = false
reverse_shell = false
```

A reverse shell additionally requires an explicit host and port. There is no compiled-in
destination. Enabling these features materially changes the exposure of the guest; use a private,
disposable network and preserve the policy alongside test evidence.

## Secret handling rules

- Never place passwords in policy, source, command output, or an automation prompt.
- Pass remote authentication through an interactive prompt or an ephemeral process environment.
- Never copy an environment directory into a build, remote source bundle, or tool directory.
- Treat full-disk backups as sensitive even when no generated key is embedded in stock firmware.
- Before distribution, scan the complete archive for OpenSSH private-key markers and known legacy
  credentials.
