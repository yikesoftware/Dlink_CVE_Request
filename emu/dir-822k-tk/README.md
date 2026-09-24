# D-Link DIR-822K/TK Telkom emulation

Use the archive below as the shared reproduction environment for every case under this model.

- Archive: `dlink-dir-822k-tk-v1.00-20250624-emulator.tar.zst`
- SHA-256: `82487a15eb564bb73e8d884aeb9804c84a6dec7ac303c03c367c4f2ca02ad645`

Follow the archive README for extraction, network namespace, start/stop, readiness checks, and any model-specific preparation. Each case README supplies the PoC command and expected observation.

## Included emulator instructions

# D-Link DIR-822K/TK Telkom full-system QEMU reproduction environment

- Firmware: V1.00 build 2025-06-24 (EOL)
- Firmware package SHA-256: `d5c7cd9a4991ae507e00805f011e6fb05e8baa9ac382201251c0b874cf2b0dba`
- Runtime model: system QEMU with a TAP interface; no user-mode chroot/proot execution

## Host prerequisites

Linux, Python 3, iproute2, curl, tar, zstd, and the QEMU system emulator
matching the architecture. On Debian/Ubuntu, the required emulator is provided
by the `qemu-system-mips` package.

## Start and stop

`start.sh` copies the canonical sparse disk to `runtime/image.raw`; it never
modifies `image.raw` directly.

```sh
sudo ./start.sh
./check.sh                 # repeat until READY
sudo ./stop.sh
```

See `emu.conf` for the guest address, host TAP address, and interface name.
Serial output is recorded in `runtime/qemu.serial.log`.

