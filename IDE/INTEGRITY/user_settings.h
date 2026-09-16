/* user_settings.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Green Hills INTEGRITY RTOS config: TLS 1.3 only, ECC only, no RSA/DH/old
 * TLS. Derived from examples/configs/user_settings_tls13.h with RSA and
 * X25519 turned off to match the lean source list in ../INTEGRITY/libwolfssl.gpj
 * (see that file's comment for exactly which .c files this pairs with).
 *
 * This exact macro set + file list was sanity-built and link/run tested on
 * Linux (gcc, standalone objects, no autotools) before being carried over
 * here -- see the chat history for the validation steps. It has NOT yet been
 * built with the actual `ccintarm`/`ccppc` GHS compiler; expect to iron out
 * a few INTEGRITY/MULTI-specific warnings on the first real build.
 *
 * wolfSSL is not a target INTEGRITY recognizes on its own (no __INTEGRITY
 * branch in settings.h as of this writing), so this is a generic
 * WOLFSSL_USER_SETTINGS port that leans on INTEGRITY's POSIX personality
 * (pthread.h, BSD sockets) rather than custom mutex/IO callbacks.
 *
 * Build (INTEGRITY / MULTI): see libwolfssl.gpj in this directory.
 * Sanity-check on Linux first (recommended before every change here):
 *   cp IDE/INTEGRITY/user_settings.h user_settings.h
 *   ./configure --enable-usersettings --disable-examples --disable-crypttests
 *   make
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* Platform */
/* ------------------------------------------------- */
#if 0 /* Single threaded */
    #define SINGLE_THREADED
#endif
#if 1 /* Disable filesystem: no PJFS wired up yet, use *_buffer() cert APIs */
    #define NO_FILESYSTEM
#endif
#define WOLFSSL_IGNORE_FILE_WARN

/* INTEGRITY has a POSIX personality (pthread.h) but is not a wolfSSL-
 * recognized target, so none of the RTOS branches in wc_port.h match and
 * wolfSSL_Mutex is left undefined without this. */
#define WOLFSSL_PTHREADS

#define CUSTOM_RAND_GENERATE_SEED integrity_rand_generate_seed
int integrity_rand_generate_seed(unsigned char* output, unsigned int sz);

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#if 0 /* Small code size */
    #define WOLFSSL_SP_SMALL
#endif

/* ------------------------------------------------- */
/* TLS 1.3 */
/* ------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS

/* Disable older TLS versions */
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS

/* TLS 1.3 Extensions */
#if 1 /* Session tickets */
    #define HAVE_SESSION_TICKET
#endif
#if 0 /* Early data (0-RTT) */
    #define WOLFSSL_EARLY_DATA
#endif
#if 0 /* Post-handshake authentication */
    #define WOLFSSL_POST_HANDSHAKE_AUTH
#endif
#if 1 /* Server Name Indication */
    #define HAVE_SNI
#endif

/* Client/Server */
#if 0 /* Client only */
    #define NO_WOLFSSL_SERVER
#endif
#if 0 /* Server only */
    #define NO_WOLFSSL_CLIENT
#endif

/* ------------------------------------------------- */
/* Timing Resistance */
/* ------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* ECC */
/* ------------------------------------------------- */
#if 1 /* ECC support */
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #if 1 /* P-384 */
        #define HAVE_ECC384
    #endif
    #if 0 /* P-521 */
        #define HAVE_ECC521
    #endif
    #define ECC_SHAMIR
#endif

/* ------------------------------------------------- */
/* Curve25519 / Ed25519 */
/* ------------------------------------------------- */
#if 0 /* X25519 key exchange -- off: adds curve25519.c/fe_*.c/ge_*.c,
       * which are not in the lean INTEGRITY file list below. Turn this on
       * and add those sources to libwolfssl.gpj if you want X25519 for
       * broader TLS1.3 interop (most public servers offer it). */
    #define HAVE_CURVE25519
#endif
#if 0 /* Ed25519 signatures */
    #define HAVE_ED25519
#endif

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#if 0 /* RSA support: off -- ECC only per requirements. Note most public
       * CA roots are still RSA-signed, so verifying real-world server
       * chains (vs. an all-ECDSA private PKI) will need this turned back
       * on (and rsa.c added to libwolfssl.gpj). */
    #undef NO_RSA
    #define WOLFSSL_KEY_GEN
#else
    #define NO_RSA
#endif

/* ------------------------------------------------- */
/* DH */
/* ------------------------------------------------- */
#if 0 /* DH key exchange (FFDHE) */
    #undef NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_FFDHE_3072
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
/* AES-GCM (required for TLS 1.3) */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#if 1 /* ChaCha20-Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #define HAVE_ONE_TIME_AUTH
#endif

#if 0 /* AES-CCM */
    #define HAVE_AESCCM
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 required */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

#if 0 /* Certificate generation */
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_EXT
#endif

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

/* ------------------------------------------------- */
/* TI SA2UL Hardware Acceleration (crypto callback) */
/* ------------------------------------------------- */
/* Staged port: registers a WOLF_CRYPTO_CB device for AES-CBC/ECB/GCM and
 * SHA256/SHA512, but every handler is currently a stub that falls back
 * to software -- the mcu_plus_sdk SA2UL driver this needs to actually
 * touch hardware isn't in this tree yet. See
 * wolfcrypt/src/port/ti/README_sa2ul.md and ti-sa2ul_port.c's own header
 * comment. TRNG is NOT part of this -- that's rng_driver.c, unrelated
 * and already working (direct register access via IODevice). */
#define WOLFSSL_TI_AM64X
#define HAVE_AES_ECB
/* wc_Sha512 is shared with SHA384 (both defined above); this port's
 * SHA512 dispatch needs to tell them apart. */
#define WOLFSSL_SHA512_HASHTYPE
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif
#define WOLF_CRYPTO_CB_FREE

/* ------------------------------------------------- */
/* Static Memory */
/* ------------------------------------------------- */
/* wolfcrypt_test()/benchmark_test() each allocate their own fixed pool
 * (gTestMemory/gBenchMemory in test.c/benchmark.c) instead of using the
 * heap directly when this is defined -- see WOLFSSL_STATIC_MEMORY_TEST_SZ
 * below for the size of each. */
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY_TEST_SZ (100 * 1024)

/* ------------------------------------------------- */
/* Benchmark */
/* ------------------------------------------------- */
/* Scales down benchmark_test()'s buffer sizes/iteration counts for
 * constrained (non-desktop-class) targets. */
#define BENCH_EMBEDDED

/* ------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------- */
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#endif
#if 0 /* Disable error strings to save flash */
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
