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

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* Platform */
/* ------------------------------------------------- */
#if 0
    #define SINGLE_THREADED
#endif
#if 1
    #define NO_FILESYSTEM
#endif
#define WOLFSSL_IGNORE_FILE_WARN

#define WOLFSSL_PTHREADS

#define CUSTOM_RAND_GENERATE_SEED integrity_rand_generate_seed
int integrity_rand_generate_seed(unsigned char* output, unsigned int sz);

#define WOLFSSL_SP_MATH_ALL
#if 0
    #define WOLFSSL_SP_SMALL
#endif

#define WOLFSSL_AARCH64_BUILD
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_INLINE
#define WOLFSSL_SP_ASM
#define WOLFSSL_SP_ARM64
#define WOLFSSL_SP_ARM64_ASM

#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS

#if 1
    #define HAVE_SESSION_TICKET
#endif
#if 0
    #define WOLFSSL_EARLY_DATA
#endif
#if 0
    #define WOLFSSL_POST_HANDSHAKE_AUTH
#endif
#if 1
    #define HAVE_SNI
#endif
#if 0
    #define NO_WOLFSSL_SERVER
#endif
#if 0
    #define NO_WOLFSSL_CLIENT
#endif

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#if 1
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #if 1
        #define HAVE_ECC384
    #endif
    #if 0
        #define HAVE_ECC521
    #endif
    #define ECC_SHAMIR
#endif

#if 0
    #define HAVE_CURVE25519
#endif
#if 0
    #define HAVE_ED25519
#endif

#if 0
    #undef NO_RSA
    #define WOLFSSL_KEY_GEN
#else
    #define NO_RSA
#endif

#if 0
    #undef NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_FFDHE_3072
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#if 1
    #define HAVE_CHACHA
#endif

#if 0
    #define HAVE_AESCCM
#endif

#if 1
    #define WOLFSSL_CMAC
    #define WOLFSSL_AES_DIRECT
#endif

#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define HAVE_HASHDRBG

#define WOLFSSL_ASN_TEMPLATE

#if 0
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_EXT
#endif

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

#define WOLFSSL_TI_AM64X_A53_INTEGRITY
#define HAVE_AES_ECB
#define WOLFSSL_SHA512_HASHTYPE
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif
#define WOLF_CRYPTO_CB_FREE

/* these are turned off until we can integrate with the correct integrity bsp */
#if 0
    #define WOLFSSL_SA2UL_DRIVER
    #define WOLF_CRYPTO_CB_AES_SETKEY
#endif

#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY_TEST_SZ (256 * 1024)
#define BENCH_EMBEDDED

#if 0
    #define DEBUG_WOLFSSL
#endif
#if 0
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
