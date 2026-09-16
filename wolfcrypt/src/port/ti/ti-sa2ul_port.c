/* ti-sa2ul_port.c
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

/* WOLF_CRYPTO_CB device for the AM64x SA2UL: registers itself as a
 * crypto callback device and gets first refusal at AES-CBC/ECB/GCM and
 * SHA256/SHA512 operations before wolfCrypt's own software falls back.
 *
 * STAGED PORT -- STUBBED, NOT YET HARDWARE-ACCELERATED. Ported from
 * wolfSSL's TI AM64x SA2UL port (wolfBoot's lib/wolfssl,
 * wolfcrypt/src/port/ti/ti-sa2ul_port.c, WOLFSSL_TI_AM64X), which drives
 * the real hardware through TI's mcu_plus_sdk_am64x SA2UL driver
 * (security/security_common/drivers/crypto/sa2ul/sa2ul.h and friends).
 * That SDK is not part of this tree yet ("we will port over the mcu
 * plus sdk stuff later"), so every per-algorithm handler below is a
 * stub that returns CRYPTOCB_UNAVAILABLE -- wolfCrypt's documented
 * signal to fall back to its own software implementation. Nothing here
 * touches SA2UL hardware yet; this just gets the WOLF_CRYPTO_CB
 * plumbing (device registration, the algo_type/cipher.type/hash.type
 * dispatch shape, WC_USE_DEVID wiring into wolfcrypt_test()/
 * benchmark_test()) in place and exercised end to end first.
 *
 * To finish this port later: open wolfBoot's ti-sa2ul_port.c side by
 * side with this file and, function by function, replace each stub
 * body below with the real SA2UL_ContextParams/SA2UL_contextAlloc/
 * SA2UL_contextProcess/SA2UL_contextFree sequence from there (each stub
 * names its upstream counterpart). That also means adding an
 * SA2UL_ContextObject-typed context field (upstream calls it scObj) to
 * struct Aes/wc_Sha256/wc_Sha512 (wolfssl/wolfcrypt/aes.h/sha256.h/
 * sha512.h) -- deliberately not added here, since its type only exists
 * once sa2ul.h is ported.
 *
 * TRNG acceleration is deliberately NOT ported here at all -- see
 * ti-sa2ul_port.h's header comment. This file's own hardware init
 * (Crypto_open() in upstream) is skipped for the same staged reason:
 * ti_sa2ul_port_init() below only registers the (stubbed) crypto
 * callback device.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_TI_AM64X)

#ifndef WOLF_CRYPTO_CB
    #error WOLFSSL_TI_AM64X support requires ./configure --enable-cryptocb or WOLF_CRYPTO_CB to be defined
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/ti/ti-sa2ul_port.h>

#if !defined(NO_AES) && !defined(WOLFSSL_TI_AM64X_NO_AES)
static int check_aes_keylength(word32 keylen)
{
    /* The mcu_plus_sdk SA2UL driver only supports key lengths of 128 and
     * 256 -- kept here (SDK-independent logic) so the real handlers
     * inherit the right fallback-to-software behavior for AES-192 once
     * they're filled in. */
    if (keylen != AES_128_KEY_SIZE && keylen != AES_256_KEY_SIZE)
        return BAD_FUNC_ARG;

#if !defined(WOLFSSL_AES_128)
    if (keylen == AES_128_KEY_SIZE)
        return BAD_FUNC_ARG;
#endif

#if !defined(WOLFSSL_AES_256)
    if (keylen == AES_256_KEY_SIZE)
        return BAD_FUNC_ARG;
#endif

    return 0;
}

#ifdef HAVE_AES_CBC
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesCbcEncrypt(). */
static int ti_sa2ul_AesCbcEncrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
}

#ifdef HAVE_AES_DECRYPT
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesCbcDecrypt(). */
static int ti_sa2ul_AesCbcDecrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AES_ECB
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesEcbEncrypt(). */
static int ti_sa2ul_AesEcbEncrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
}

#ifdef HAVE_AES_DECRYPT
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesEcbDecrypt(). */
static int ti_sa2ul_AesEcbDecrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesGcmEncrypt(). */
static int ti_sa2ul_AesGcmEncrypt(Aes* aes, byte* out,
        const byte* in, word32 sz,
        const byte* iv, word32 ivSz,
        byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz)
{
    (void)aes; (void)out; (void)in; (void)sz;
    (void)iv; (void)ivSz; (void)authTag; (void)authTagSz;
    (void)authIn; (void)authInSz;
    return CRYPTOCB_UNAVAILABLE;
}

#ifdef HAVE_AES_DECRYPT
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesGcmDecrypt(). */
static int ti_sa2ul_AesGcmDecrypt(Aes* aes, byte* out,
        const byte* in, word32 sz,
        const byte* iv, word32 ivSz,
        const byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz)
{
    (void)aes; (void)out; (void)in; (void)sz;
    (void)iv; (void)ivSz; (void)authTag; (void)authTagSz;
    (void)authIn; (void)authInSz;
    return CRYPTOCB_UNAVAILABLE;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */
#endif /* !NO_AES && !WOLFSSL_TI_AM64X_NO_AES */

#if !defined(WOLFSSL_TI_AM64X_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
#ifndef NO_SHA256
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_Sha256Hash() (block-by-
 * block SA2UL_contextProcess(), matching wolfCrypt's usual incremental
 * hash update/final shape -- see wolfBoot's version for the full leftover-
 * buffering state machine). */
static int ti_sa2ul_Sha256Hash(wc_Sha256* sha256, const byte* in,
        word32 inSz, byte* digest)
{
    (void)sha256; (void)in; (void)inSz; (void)digest;
    return CRYPTOCB_UNAVAILABLE;
}

/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_Sha256Teardown() (only
 * needed once ti_sa2ul_Sha256Hash() above can actually leave a SA2UL
 * hardware context allocated for this wc_Sha256 to tear down). */
static int ti_sa2ul_Sha256Teardown(wc_Sha256* sha256)
{
    (void)sha256;
    return 0;
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA512
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_Sha512Hash(). */
static int ti_sa2ul_Sha512Hash(wc_Sha512* sha512, const byte* in,
        word32 inSz, byte* digest)
{
    (void)sha512; (void)in; (void)inSz; (void)digest;
    return CRYPTOCB_UNAVAILABLE;
}

/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_Sha512Teardown(). */
static int ti_sa2ul_Sha512Teardown(wc_Sha512* sha512)
{
    (void)sha512;
    return 0;
}
#endif /* WOLFSSL_SHA512 */
#endif /* !WOLFSSL_TI_AM64X_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */

static int ti_sa2ul_CryptoDevCb(int devId, wc_CryptoInfo* info, void* devCtx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    WOLFSSL_ENTER("ti_sa2ul_CryptoDevCb");

    (void)devCtx;

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (devId == INVALID_DEVID)
        return CRYPTOCB_UNAVAILABLE;

#ifdef DEBUG_CRYPTOCB
    wc_CryptoCb_InfoString(info);
#endif

    if (info->algo_type == WC_ALGO_TYPE_CIPHER)
    {
#if !defined(NO_AES) && !defined(WOLFSSL_TI_AM64X_NO_AES)
        if (0) {
            /* nothing */
        }
# if defined(HAVE_AES_CBC)
        else if (info->cipher.type == WC_CIPHER_AES_CBC) {
            Aes* aes = info->cipher.aescbc.aes;
            if (aes == NULL)
                return BAD_FUNC_ARG;
            if (check_aes_keylength(aes->keylen) != 0)
                return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
            if (info->cipher.enc) {
                ret = ti_sa2ul_AesCbcEncrypt(info->cipher.aescbc.aes,
                                             info->cipher.aescbc.out,
                                             info->cipher.aescbc.in,
                                             info->cipher.aescbc.sz);
            }
#  ifdef HAVE_AES_DECRYPT
            else {
                ret = ti_sa2ul_AesCbcDecrypt(info->cipher.aescbc.aes,
                                             info->cipher.aescbc.out,
                                             info->cipher.aescbc.in,
                                             info->cipher.aescbc.sz);
            }
#  endif /* HAVE_AES_DECRYPT */
        }
# endif /* HAVE_AES_CBC */
# if defined(HAVE_AES_ECB)
        else if (info->cipher.type == WC_CIPHER_AES_ECB) {
            Aes* aes = info->cipher.aesecb.aes;
            if (aes == NULL)
                return BAD_FUNC_ARG;
            if (check_aes_keylength(aes->keylen) != 0)
                return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
            if (info->cipher.enc) {
                ret = ti_sa2ul_AesEcbEncrypt(info->cipher.aesecb.aes,
                                             info->cipher.aesecb.out,
                                             info->cipher.aesecb.in,
                                             info->cipher.aesecb.sz);
            }
#  ifdef HAVE_AES_DECRYPT
            else {
                ret = ti_sa2ul_AesEcbDecrypt(info->cipher.aesecb.aes,
                                             info->cipher.aesecb.out,
                                             info->cipher.aesecb.in,
                                             info->cipher.aesecb.sz);
            }
#  endif /* HAVE_AES_DECRYPT */
        }
# endif /* HAVE_AES_ECB */
# if defined(HAVE_AESGCM)
        else if (info->cipher.type == WC_CIPHER_AES_GCM) {
            if (info->cipher.enc) {
                Aes* aes = info->cipher.aesgcm_enc.aes;
                if (aes == NULL)
                    return BAD_FUNC_ARG;
                if (check_aes_keylength(aes->keylen) != 0 ||
                    info->cipher.aesgcm_enc.sz == 0) {
                        return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
                }
                ret = ti_sa2ul_AesGcmEncrypt(aes,
                        info->cipher.aesgcm_enc.out,
                        info->cipher.aesgcm_enc.in,
                        info->cipher.aesgcm_enc.sz,
                        info->cipher.aesgcm_enc.iv,
                        info->cipher.aesgcm_enc.ivSz,
                        info->cipher.aesgcm_enc.authTag,
                        info->cipher.aesgcm_enc.authTagSz,
                        info->cipher.aesgcm_enc.authIn,
                        info->cipher.aesgcm_enc.authInSz);
            }
#  ifdef HAVE_AES_DECRYPT
            else {
                Aes* aes = info->cipher.aesgcm_dec.aes;
                if (aes == NULL)
                    return BAD_FUNC_ARG;
                if (check_aes_keylength(aes->keylen) != 0 ||
                    info->cipher.aesgcm_dec.sz == 0) {
                        return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
                }
                ret = ti_sa2ul_AesGcmDecrypt(aes,
                        info->cipher.aesgcm_dec.out,
                        info->cipher.aesgcm_dec.in,
                        info->cipher.aesgcm_dec.sz,
                        info->cipher.aesgcm_dec.iv,
                        info->cipher.aesgcm_dec.ivSz,
                        info->cipher.aesgcm_dec.authTag,
                        info->cipher.aesgcm_dec.authTagSz,
                        info->cipher.aesgcm_dec.authIn,
                        info->cipher.aesgcm_dec.authInSz);
            }
#  endif /* HAVE_AES_DECRYPT */
        }
# endif /* HAVE_AESGCM */
#endif /* !NO_AES && !WOLFSSL_TI_AM64X_NO_AES */
    }
    else if (info->algo_type == WC_ALGO_TYPE_HASH)
    {
#if !defined(WOLFSSL_TI_AM64X_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
        if (0) {
            /* nothing */
        }
# ifndef NO_SHA256
        else if (info->hash.type == WC_HASH_TYPE_SHA256) {
            if ((info->hash.sha256->flags & WC_HASH_FLAG_ISCOPY) == 0) {
                ret = ti_sa2ul_Sha256Hash(info->hash.sha256,
                                          info->hash.in,
                                          info->hash.inSz,
                                          info->hash.digest);
            }
        }
# endif /* !NO_SHA256 */
# ifdef WOLFSSL_SHA512
        else if (info->hash.type == WC_HASH_TYPE_SHA512) {
            if (info->hash.sha512->hashType == WC_HASH_TYPE_SHA512 &&
                (info->hash.sha512->flags & WC_HASH_FLAG_ISCOPY) == 0) {
                ret = ti_sa2ul_Sha512Hash(info->hash.sha512,
                                          info->hash.in,
                                          info->hash.inSz,
                                          info->hash.digest);
                }
        }
# endif /* WOLFSSL_SHA512 */
#endif /* !WOLFSSL_TI_AM64X_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */
    }
#ifdef WOLF_CRYPTO_CB_FREE
    else if (info->algo_type == WC_ALGO_TYPE_FREE)
    {
# if !defined(WOLFSSL_TI_AM64X_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
        if (info->free.algo == WC_ALGO_TYPE_HASH) {
            if (0) {
                /* nothing */
            }
#  ifndef NO_SHA256
            else if (info->free.type == WC_HASH_TYPE_SHA256) {
                wc_Sha256* sha256 = (wc_Sha256*)info->free.obj;
                if ((sha256->flags & WC_HASH_FLAG_ISCOPY) == 0) {
                    ret = ti_sa2ul_Sha256Teardown(sha256);
                }
            }
#  endif /* !NO_SHA256 */
#  ifdef WOLFSSL_SHA512
            else if (info->free.type == WC_HASH_TYPE_SHA512) {
                wc_Sha512* sha512 = (wc_Sha512*)info->free.obj;
                if (sha512->hashType == WC_HASH_TYPE_SHA512 &&
                    (sha512->flags & WC_HASH_FLAG_ISCOPY) == 0) {
                    ret = ti_sa2ul_Sha512Teardown(sha512);
                }
            }
#  endif /* WOLFSSL_SHA512 */
        }
# endif /* !WOLFSSL_TI_AM64X_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */
    }
#endif /* WOLF_CRYPTO_CB_FREE */

    return ret;
}

int ti_sa2ul_port_init(void)
{
    /* TODO(mcu_plus_sdk port): upstream also brings up the TRNG here
     * (this project's TRNG is rng_driver.c instead -- see this file's
     * header comment) and opens the real SA2UL hardware context
     * (Crypto_open(&cryptoCtx)) before registering the callback device.
     * Skipped for now: every handler above is a stub, so there's no
     * hardware context to open yet. */
    return wc_CryptoCb_RegisterDevice(WOLFSSL_TI_SA2UL_DEVID,
                                       ti_sa2ul_CryptoDevCb, NULL);
}

#endif /* WOLFSSL_TI_AM64X */
