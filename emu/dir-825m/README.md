# D-Link DIR-825M Hardware A1 emulation

Use the archive below as the shared reproduction environment for every case under this model.

- Archive: `dlink-dir-825m-1.1.8.6-emulator.tar.zst`
- SHA-256: `b91b38b7fe21cc3043023169d638f42228bf2e0f7a3f02da4101071640289ee5`

Follow the archive README for extraction, network namespace, start/stop, readiness checks, and any model-specific preparation. Each case README supplies the PoC command and expected observation.

## Included emulator instructions

# D-Link DIR-825M Hardware A1 full-system QEMU reproduction environment

- Firmware: 1.1.8.6
- Firmware package SHA-256: `3bb7e23c15b71dc20a0f69e33315c37f99e4818c04120dfa7519f1bfe4e23ad0`
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

