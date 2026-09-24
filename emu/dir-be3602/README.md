# D-Link DIR-BE3602 emulation

Use the archive below as the shared reproduction environment for every case under this model.

- Archive: `dlink-dir-be3602-1.04-emulator.tar.zst`
- SHA-256: `49844d04ebf0ffc6ed4a09f21a262901d402b16ae6232561710276568244600c`

Follow the archive README for extraction, network namespace, start/stop, readiness checks, and any model-specific preparation. Each case README supplies the PoC command and expected observation.

## Included emulator instructions

# D-Link DIR-BE3602 1.04 full-system QEMU reproduction environment

- Firmware: DIR-BE3602 1.04, build 2025-07-21
- Firmware package SHA-256: `e09a0c6b9f87c16dd8ee2cdfe70f88553f1ba69a33d6f0fbf7daf5969ea3aa2a`
- Guest service: TLS framed-JSON service on `192.168.210.1:18169`
- Host TAP address: `192.168.210.2/24`
- Runtime model: system QEMU with a TAP interface; no user-mode chroot/proot execution

The vendor user space and libraries are from DIR-BE3602. The original IPQ5332
kernel requires its physical SoC, so this package uses a generic ARM32 carrier
kernel to boot the unchanged vendor user space. This limitation does not replace
or patch the reported `web-api` code path.

## Host prerequisites

Linux, Python 3, iproute2, tar, zstd, and `qemu-system-arm`.

## Start and stop

`start.sh` stays attached to terminal A and writes serial output to
`runtime/qemu.final.serial.log`. It copies the canonical image before launch.

```sh
sudo ./start.sh
```

After approximately 70 seconds, verify the TLS listener from another terminal:

```sh
timeout 5 openssl s_client -connect 192.168.210.1:18169 </dev/null
```

Stop it from another terminal:

```sh
sudo ./stop.sh
```

