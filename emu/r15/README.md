# D-Link R15 Hardware A1 emulation

Use the archive below as the shared reproduction environment for every case under this model.

- Archive: `dlink-r15-a1-1.22-emulator.tar.zst`
- SHA-256: `d301b88840693e2f1b0891cc948f004f2db9ecf0d1325f5168de479bb0e9c1d3`

Follow the archive README for extraction, network namespace, start/stop, readiness checks, and any model-specific preparation. Each case README supplies the PoC command and expected observation.

## Included emulator instructions

# D-Link R15 Hardware A1 full-system QEMU reproduction environment

- Firmware: 1.22
- Firmware package SHA-256: `0f467fa1741eff2a9966749b9720b7f52f07161e2bd7e4eba2a9dd0186871b1d`
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

## V048 configuration state

The firmware startup sequence resets its HTTP-compression setting on every boot.
After `check.sh` reports `READY`, run `python3 ./enable-v048.py`. The helper uses
the emulator's debug console to set native `CSMAN` item `131078` to `3` (gzip
and deflate) and restart the unmodified firmware `httpd`. It does not patch the
reported code or any library. V047 does not depend on this option.

