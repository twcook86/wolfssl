# wolfSSL TI SA2UL Hardware Acceleration Port (staged, stubbed)

wolfSSL supports hardware acceleration on the TI AM64x via the SA2UL peripheral,
through a WOLF_CRYPTO_CB device (`ti-sa2ul_a53_integrity_port.c`/`.h`).

**Current status in this tree: two separate layers, at two different stages.**

1. **The Kernel-linked hardware driver** (`IDE/INTEGRITY/sa2ul_driver.c` +
   `sa2ul_devtree_driver.c`/`sa2ul_iodevice.h`/`sa2ul_iodevice_server.c`) is a
   direct, byte-for-byte port of TI's mcu_plus_sdk_am64x SA2UL driver
   (`security/security_common/drivers/crypto/sa2ul/sa2ul.c`/`.h`) onto this
   INTEGRITY BSP's own DMA API, covering **both** AES (ECB/CBC/GCM, 128/256)
   and plain SHA-1/SHA-256/SHA-512 hashing (`SA2UL_OP_AUTH`, not HMAC -- see
   `sa2ul_driver.c`'s own header comment). Restored for review, **not** wired
   into the active build -- see `IDE/INTEGRITY/sa2ul_driver.c`'s and
   `proj/myproject_kernel.gpj`/`proj/myproject.int`'s own comments: it's
   still blocked on a missing GHS BSP header
   (`support/reg_access_ioacl.h`), gated behind `WOLFSSL_SA2UL_DRIVER`.
2. **`ti-sa2ul_a53_integrity_port.c`** (the Task-linked WOLF_CRYPTO_CB device that would
   actually call through to (1) via the "Sa2ulDev" IODevice) is still
   plumbing-only: every per-algorithm handler is a stub that returns
   `CRYPTOCB_UNAVAILABLE`, so wolfCrypt transparently falls back to its own
   software implementation for everything. Layer (1) being ready doesn't
   change this by itself -- `ti-sa2ul_a53_integrity_port.c` still needs to be rewritten to
   call `RequestResource("Sa2ulDev")`/`ReadIODeviceStatus()` (matching
   `sa2ul_iodevice.h`'s `struct Sa2ulCtrl`/`Sa2ulData` contract) in place of
   each stub body, instead of the direct in-process
   `SA2UL_contextAlloc()`/`SA2UL_contextProcess()` calls wolfBoot's
   `lib/wolfssl/wolfcrypt/src/port/ti/ti-sa2ul_a53_integrity_port.c` reference
   implementation uses (wolfBoot has no Kernel/Task split, so it can call
   the driver directly -- this project can't). See `ti-sa2ul_a53_integrity_port.c`'s own
   header comment for the per-stub porting notes.

TRNG acceleration is intentionally NOT part of this port at all, staged or
otherwise -- this project's entropy source is `rng_driver.c` (direct SA2UL/
CP_ACE TRNG register access from Kernel-linked code, exposed to Tasks as an
IODevice; see that file's own header comment). Do not add
`CUSTOM_RAND_GENERATE_SEED`/`_BLOCK` here.

## Algorithms this port's dispatch shape covers (once un-stubbed)

- AES-ECB (128, 256)
- AES-CBC (128, 256)
- AES-GCM (128, 256)
- SHA256, SHA512
- HMAC-SHA256, HMAC-SHA512 (free once SHA256/SHA512 are accelerated --
  wolfCrypt's HMAC is built on top of the hash primitives, no separate
  WOLF_CRYPTO_CB hook needed)

### Build switches

**`WOLFSSL_TI_AM64X_A53_INTEGRITY`** -- enables this port (currently: the stubbed plumbing
only). Set in `IDE/INTEGRITY/user_settings.h`.

**`WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_AES`** / **`WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA`** -- once real
hardware acceleration lands, these disable AES or SHA acceleration
respectively (falling back to wolfCrypt software) without disabling the rest
of this port.

## Support

For questions please email support@wolfssl.com
