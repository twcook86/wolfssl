/* ti-sa2ul_a53_integrity_port.c
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

/* WOLF_CRYPTO_CB device for the AM64x SA2UL: registers itself as a crypto
 * callback device and gets first refusal at AES-CBC/ECB/GCM and SHA256/512
 * operations before wolfCrypt's own software falls back.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_TI_AM64X_A53_INTEGRITY)

#ifndef WOLF_CRYPTO_CB
    #error WOLFSSL_TI_AM64X_A53_INTEGRITY support requires ./configure --enable-cryptocb or WOLF_CRYPTO_CB to be defined
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/ti/ti-sa2ul_a53_integrity_port.h>

#ifdef WOLFSSL_SA2UL_DRIVER
#include <INTEGRITY.h>
#include <string.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h> /* GCM_NONCE_MID_SZ */
#include "sa2ul_iodevice.h"

static IODevice gSa2ulDev = NULL;
static MemoryRegion gSa2ulCtrlMr = NULLMemoryRegion;
static MemoryRegion gSa2ulDataMr = NULLMemoryRegion;
static volatile struct Sa2ulCtrl *gSa2ulCtrl = NULL;
static volatile struct Sa2ulData *gSa2ulData = NULL;

#include "myproject_integrate.h"

static int ti_sa2ul_iodevice_open(void)
{
    Address VirtFirst, VirtLast;

    if (gSa2ulDev != NULL) {
        return 0;
    }
    if (RequestResource((Object *)&gSa2ulDev, SA2UL_IODEVICE_NAME,
            "!systempassword") != Success) {
        gSa2ulDev = NULL;
        return -1;
    }

    gSa2ulCtrlMr = sa2ul_ctrl_local;
    if (GetMemoryRegionAddresses(gSa2ulCtrlMr, &VirtFirst, &VirtLast) != Success ||
            (VirtLast - VirtFirst + 1) < sizeof(struct Sa2ulCtrl)) {
        gSa2ulDev = NULL;
        return -1;
    }
    gSa2ulCtrl = (volatile struct Sa2ulCtrl *)VirtFirst;

    gSa2ulDataMr = sa2ul_data_local;
    if (GetMemoryRegionAddresses(gSa2ulDataMr, &VirtFirst, &VirtLast) != Success ||
            (VirtLast - VirtFirst + 1) < sizeof(struct Sa2ulData)) {
        gSa2ulDev = NULL;
        return -1;
    }
    gSa2ulData = (volatile struct Sa2ulData *)VirtFirst;

    return 0;
}

static int ti_sa2ul_IodeviceCall(struct Sa2ulCtrl *Ctrl, const byte *In,
        word32 InSz, byte *Out, word32 OutSz)
{
    byte dummy = 0;

    if (ti_sa2ul_iodevice_open() != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (InSz > SA2UL_MAX_BUF || OutSz > SA2UL_MAX_BUF) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (In != NULL && InSz != 0u) {
        if (CopyToMemoryRegionWithFlags(gSa2ulDataMr,
                (ExtendedAddress)(uintptr_t)gSa2ulData, (void *)In, InSz,
                ACCESS_DST_COHERENT) != Success) {
            return CRYPTOCB_UNAVAILABLE;
        }
    }

    if (CopyToMemoryRegionWithFlags(gSa2ulCtrlMr,
            (ExtendedAddress)(uintptr_t)gSa2ulCtrl, Ctrl, sizeof(*Ctrl),
            ACCESS_DST_COHERENT) != Success) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (ReadIODeviceStatus(gSa2ulDev, SA2UL_IODEVICE_STATUS_NUMBER,
            &dummy, 1) != Success) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (CopyFromMemoryRegionWithFlags(gSa2ulCtrlMr,
            (ExtendedAddress)(uintptr_t)gSa2ulCtrl, Ctrl, sizeof(*Ctrl),
            ACCESS_SRC_COHERENT) != Success) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (Out != NULL && OutSz != 0u) {
        if (CopyFromMemoryRegionWithFlags(gSa2ulDataMr,
                (ExtendedAddress)(uintptr_t)gSa2ulData, Out, OutSz,
                ACCESS_SRC_COHERENT) != Success) {
            return CRYPTOCB_UNAVAILABLE;
        }
    }

    return 0;
}

#ifndef SA2UL_AES_KEY_CACHE_SIZE
#define SA2UL_AES_KEY_CACHE_SIZE 4
#endif

struct Sa2ulAesKeyCacheEntry {
    const Aes *owner;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;
};

static struct Sa2ulAesKeyCacheEntry gSa2ulAesKeyCache[SA2UL_AES_KEY_CACHE_SIZE];
static unsigned int gSa2ulAesKeyCacheNext = 0;

static void ti_sa2ul_AesCacheKey(const Aes *aes, const byte *key, word32 keySz)
{
    unsigned int i;

    if (keySz > SA2UL_MAX_KEY_BYTES) {
        return; /* can't happen for 128/256-bit AES keys, but stay safe */
    }
    for (i = 0; i < SA2UL_AES_KEY_CACHE_SIZE; i++) {
        if (gSa2ulAesKeyCache[i].owner == aes) {
            memcpy(gSa2ulAesKeyCache[i].key, key, keySz);
            gSa2ulAesKeyCache[i].keySz = keySz;
            return;
        }
    }
    i = gSa2ulAesKeyCacheNext;
    gSa2ulAesKeyCacheNext = (gSa2ulAesKeyCacheNext + 1u) % SA2UL_AES_KEY_CACHE_SIZE;
    gSa2ulAesKeyCache[i].owner = aes;
    memcpy(gSa2ulAesKeyCache[i].key, key, keySz);
    gSa2ulAesKeyCache[i].keySz = keySz;
}

/* Returns 0 and fills *KeyOut and *KeySzOut on a cache hit, -1 on a miss. */
static int ti_sa2ul_AesLookupKey(const Aes *aes, byte KeyOut[SA2UL_MAX_KEY_BYTES],
        word32 *KeySzOut)
{
    unsigned int i;

    for (i = 0; i < SA2UL_AES_KEY_CACHE_SIZE; i++) {
        if (gSa2ulAesKeyCache[i].owner == aes) {
            memcpy(KeyOut, gSa2ulAesKeyCache[i].key, gSa2ulAesKeyCache[i].keySz);
            *KeySzOut = gSa2ulAesKeyCache[i].keySz;
            return 0;
        }
    }
    return -1;
}

static int ti_sa2ul_AesSetKey(Aes *aes, const byte *key, word32 keySz)
{
    ti_sa2ul_AesCacheKey(aes, key, keySz);
    return CRYPTOCB_UNAVAILABLE;
}

static byte gSa2ulHashAccum[SA2UL_MAX_BUF];
static word32 gSa2ulHashAccumLen = 0;
static const void *gSa2ulHashOwner = NULL;

#endif /* WOLFSSL_SA2UL_DRIVER */

#if !defined(NO_AES) && !defined(WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_AES)
static int check_aes_keylength(word32 keylen)
{
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
#ifdef WOLFSSL_SA2UL_DRIVER
    struct Sa2ulCtrl ctrl;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;

    if (sz == 0u || (sz % WC_AES_BLOCK_SIZE) != 0u || sz > SA2UL_MAX_BUF) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ti_sa2ul_AesLookupKey(aes, key, &keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.op = SA2UL_OP_AES_CBC_ENCRYPT;
    ctrl.sz = sz;
    ctrl.keyBytes = keySz;
    memcpy(ctrl.key, key, keySz);
    memcpy(ctrl.iv, aes->reg, WC_AES_BLOCK_SIZE);

    if (ti_sa2ul_IodeviceCall(&ctrl, in, sz, out, sz) != 0 ||
            ctrl.ret != SA2UL_DRIVER_OK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memcpy(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);

    return 0;
#else
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

#ifdef HAVE_AES_DECRYPT
/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_AesCbcDecrypt(). */
static int ti_sa2ul_AesCbcDecrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    struct Sa2ulCtrl ctrl;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;
    byte nextIv[WC_AES_BLOCK_SIZE];

    if (sz == 0u || (sz % WC_AES_BLOCK_SIZE) != 0u || sz > SA2UL_MAX_BUF) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ti_sa2ul_AesLookupKey(aes, key, &keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memcpy(nextIv, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.op = SA2UL_OP_AES_CBC_DECRYPT;
    ctrl.sz = sz;
    ctrl.keyBytes = keySz;
    memcpy(ctrl.key, key, keySz);
    memcpy(ctrl.iv, aes->reg, WC_AES_BLOCK_SIZE);

    if (ti_sa2ul_IodeviceCall(&ctrl, in, sz, out, sz) != 0 ||
            ctrl.ret != SA2UL_DRIVER_OK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memcpy(aes->reg, nextIv, WC_AES_BLOCK_SIZE);

    return 0;
#else
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
#endif
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AES_ECB
static int ti_sa2ul_AesEcbEncrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    struct Sa2ulCtrl ctrl;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;

    if (sz == 0u || (sz % WC_AES_BLOCK_SIZE) != 0u || sz > SA2UL_MAX_BUF) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ti_sa2ul_AesLookupKey(aes, key, &keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.op = SA2UL_OP_AES_ECB_ENCRYPT;
    ctrl.sz = sz;
    ctrl.keyBytes = keySz;
    memcpy(ctrl.key, key, keySz);

    if (ti_sa2ul_IodeviceCall(&ctrl, in, sz, out, sz) != 0 ||
            ctrl.ret != SA2UL_DRIVER_OK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
#else
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

#ifdef HAVE_AES_DECRYPT
static int ti_sa2ul_AesEcbDecrypt(Aes* aes, byte* out, const byte* in,
        word32 sz)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    struct Sa2ulCtrl ctrl;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;

    if (sz == 0u || (sz % WC_AES_BLOCK_SIZE) != 0u || sz > SA2UL_MAX_BUF) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ti_sa2ul_AesLookupKey(aes, key, &keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.op = SA2UL_OP_AES_ECB_DECRYPT;
    ctrl.sz = sz;
    ctrl.keyBytes = keySz;
    memcpy(ctrl.key, key, keySz);

    if (ti_sa2ul_IodeviceCall(&ctrl, in, sz, out, sz) != 0 ||
            ctrl.ret != SA2UL_DRIVER_OK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
#else
    (void)aes; (void)out; (void)in; (void)sz;
    return CRYPTOCB_UNAVAILABLE;
#endif
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
#ifdef WOLFSSL_SA2UL_DRIVER
    struct Sa2ulCtrl ctrl;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;

    if (sz == 0u || sz > SA2UL_MAX_BUF || ivSz != GCM_NONCE_MID_SZ ||
            authInSz > SA2UL_MAX_AAD_BYTES || authTagSz > SA2UL_MAX_TAG_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ti_sa2ul_AesLookupKey(aes, key, &keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.op = SA2UL_OP_AES_GCM_ENCRYPT;
    ctrl.sz = sz;
    ctrl.keyBytes = keySz;
    memcpy(ctrl.key, key, keySz);
    ctrl.ivSz = ivSz;
    memcpy(ctrl.iv, iv, ivSz);
    ctrl.aadSz = authInSz;
    if (authInSz != 0u) {
        memcpy(ctrl.aad, authIn, authInSz);
    }

    if (ti_sa2ul_IodeviceCall(&ctrl, in, sz, out, sz) != 0 ||
            ctrl.ret != SA2UL_DRIVER_OK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (authTag != NULL) {
        memcpy(authTag, ctrl.tagOut, authTagSz);
    }

    return 0;
#else
    (void)aes; (void)out; (void)in; (void)sz;
    (void)iv; (void)ivSz; (void)authTag; (void)authTagSz;
    (void)authIn; (void)authInSz;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

#ifdef HAVE_AES_DECRYPT
static int ti_sa2ul_AesGcmDecrypt(Aes* aes, byte* out,
        const byte* in, word32 sz,
        const byte* iv, word32 ivSz,
        const byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    struct Sa2ulCtrl ctrl;
    byte key[SA2UL_MAX_KEY_BYTES];
    word32 keySz;

    if (sz == 0u || sz > SA2UL_MAX_BUF || ivSz != GCM_NONCE_MID_SZ ||
            authInSz > SA2UL_MAX_AAD_BYTES || authTagSz > SA2UL_MAX_TAG_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ti_sa2ul_AesLookupKey(aes, key, &keySz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.op = SA2UL_OP_AES_GCM_DECRYPT;
    ctrl.sz = sz;
    ctrl.keyBytes = keySz;
    memcpy(ctrl.key, key, keySz);
    ctrl.ivSz = ivSz;
    memcpy(ctrl.iv, iv, ivSz);
    ctrl.aadSz = authInSz;
    if (authInSz != 0u) {
        memcpy(ctrl.aad, authIn, authInSz);
    }
    memcpy(ctrl.tagIn, authTag, authTagSz);

    if (ti_sa2ul_IodeviceCall(&ctrl, in, sz, out, sz) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (ctrl.ret == SA2UL_DRIVER_AUTH_FAILED) {
        return WC_NO_ERR_TRACE(AES_GCM_AUTH_E);
    }
    if (ctrl.ret != SA2UL_DRIVER_OK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
#else
    (void)aes; (void)out; (void)in; (void)sz;
    (void)iv; (void)ivSz; (void)authTag; (void)authTagSz;
    (void)authIn; (void)authInSz;
    return CRYPTOCB_UNAVAILABLE;
#endif
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */
#endif /* !NO_AES && !WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_AES */

#if !defined(WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
#ifndef NO_SHA256
static int ti_sa2ul_Sha256Hash(wc_Sha256* sha256, const byte* in,
        word32 inSz, byte* digest)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    if (in == NULL && digest == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((sha256->flags & WC_HASH_FLAG_ISCOPY) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (in != NULL) {
        /* Update */
        if (gSa2ulHashOwner != NULL && gSa2ulHashOwner != sha256) {
            sha256->flags |= WC_HASH_FLAG_ISCOPY;
            return CRYPTOCB_UNAVAILABLE;
        }
        if (gSa2ulHashOwner == NULL) {
            if (ti_sa2ul_iodevice_open() != 0) {
                return CRYPTOCB_UNAVAILABLE;
            }
            gSa2ulHashOwner = sha256;
            gSa2ulHashAccumLen = 0;
        }
        if ((word64)gSa2ulHashAccumLen + inSz > sizeof(gSa2ulHashAccum)) {
            int ret;

            sha256->flags |= WC_HASH_FLAG_ISCOPY;
            gSa2ulHashOwner = NULL;
            ret = wc_Sha256Update(sha256, gSa2ulHashAccum, gSa2ulHashAccumLen);
            gSa2ulHashAccumLen = 0;
            if (ret != 0) {
                return ret;
            }
            return wc_Sha256Update(sha256, in, inSz);
        }
        memcpy(gSa2ulHashAccum + gSa2ulHashAccumLen, in, inSz);
        gSa2ulHashAccumLen += inSz;
        return 0;
    }
    else {
        /* Final */
        struct Sa2ulCtrl ctrl;
        int ret;

        if (gSa2ulHashOwner != sha256) {
            return CRYPTOCB_UNAVAILABLE;
        }

        memset(&ctrl, 0, sizeof(ctrl));
        ctrl.op = SA2UL_OP_SHA256;
        ctrl.sz = gSa2ulHashAccumLen;

        ret = ti_sa2ul_IodeviceCall(&ctrl, gSa2ulHashAccum, gSa2ulHashAccumLen,
                NULL, 0);
        gSa2ulHashOwner = NULL;
        gSa2ulHashAccumLen = 0;
        if (ret != 0 || ctrl.ret != SA2UL_DRIVER_OK) {
            return WC_HW_E;
        }

        memcpy(digest, ctrl.digestOut, WC_SHA256_DIGEST_SIZE);
        return 0;
    }
#else
    (void)sha256; (void)in; (void)inSz; (void)digest;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_Sha256Teardown(). */
static int ti_sa2ul_Sha256Teardown(wc_Sha256* sha256)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    if (gSa2ulHashOwner == sha256) {
        gSa2ulHashOwner = NULL;
        gSa2ulHashAccumLen = 0;
    }
    return 0;
#else
    (void)sha256;
    return 0;
#endif
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA512
static int ti_sa2ul_Sha512Hash(wc_Sha512* sha512, const byte* in,
        word32 inSz, byte* digest)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    if (in == NULL && digest == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((sha512->flags & WC_HASH_FLAG_ISCOPY) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (in != NULL) {
        if (gSa2ulHashOwner != NULL && gSa2ulHashOwner != sha512) {
            sha512->flags |= WC_HASH_FLAG_ISCOPY;
            return CRYPTOCB_UNAVAILABLE;
        }
        if (gSa2ulHashOwner == NULL) {
            if (ti_sa2ul_iodevice_open() != 0) {
                return CRYPTOCB_UNAVAILABLE;
            }
            gSa2ulHashOwner = sha512;
            gSa2ulHashAccumLen = 0;
        }
        if ((word64)gSa2ulHashAccumLen + inSz > sizeof(gSa2ulHashAccum)) {
            int ret;

            sha512->flags |= WC_HASH_FLAG_ISCOPY;
            gSa2ulHashOwner = NULL;
            ret = wc_Sha512Update(sha512, gSa2ulHashAccum, gSa2ulHashAccumLen);
            gSa2ulHashAccumLen = 0;
            if (ret != 0) {
                return ret;
            }
            return wc_Sha512Update(sha512, in, inSz);
        }
        memcpy(gSa2ulHashAccum + gSa2ulHashAccumLen, in, inSz);
        gSa2ulHashAccumLen += inSz;
        return 0;
    }
    else {
        struct Sa2ulCtrl ctrl;
        int ret;

        if (gSa2ulHashOwner != sha512) {
            return CRYPTOCB_UNAVAILABLE;
        }

        memset(&ctrl, 0, sizeof(ctrl));
        ctrl.op = SA2UL_OP_SHA512;
        ctrl.sz = gSa2ulHashAccumLen;

        ret = ti_sa2ul_IodeviceCall(&ctrl, gSa2ulHashAccum, gSa2ulHashAccumLen,
                NULL, 0);
        gSa2ulHashOwner = NULL;
        gSa2ulHashAccumLen = 0;
        if (ret != 0 || ctrl.ret != SA2UL_DRIVER_OK) {
            return WC_HW_E;
        }

        memcpy(digest, ctrl.digestOut, WC_SHA512_DIGEST_SIZE);
        return 0;
    }
#else
    (void)sha512; (void)in; (void)inSz; (void)digest;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

/* TODO(mcu_plus_sdk port): upstream's ti_sa2ul_Sha512Teardown(). */
static int ti_sa2ul_Sha512Teardown(wc_Sha512* sha512)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    if (gSa2ulHashOwner == sha512) {
        gSa2ulHashOwner = NULL;
        gSa2ulHashAccumLen = 0;
    }
    return 0;
#else
    (void)sha512;
    return 0;
#endif
}
#endif /* WOLFSSL_SHA512 */
#endif /* !WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */

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
#if !defined(NO_AES) && !defined(WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_AES)
        if (0) {
            /* nothing */
        }
# if defined(WOLFSSL_SA2UL_DRIVER) && defined(WOLF_CRYPTO_CB_AES_SETKEY)
        else if (info->cipher.type == WC_CIPHER_AES) {
            ret = ti_sa2ul_AesSetKey(info->cipher.aessetkey.aes,
                                      info->cipher.aessetkey.key,
                                      info->cipher.aessetkey.keySz);
        }
# endif /* WOLFSSL_SA2UL_DRIVER && WOLF_CRYPTO_CB_AES_SETKEY */
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
#endif /* !NO_AES && !WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_AES */
    }
    else if (info->algo_type == WC_ALGO_TYPE_HASH)
    {
#if !defined(WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
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
#endif /* !WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */
    }
#ifdef WOLF_CRYPTO_CB_FREE
    else if (info->algo_type == WC_ALGO_TYPE_FREE)
    {
# if !defined(WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
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
# endif /* !WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */
    }
#endif /* WOLF_CRYPTO_CB_FREE */

    return ret;
}

int ti_sa2ul_port_init(void)
{
    return wc_CryptoCb_RegisterDevice(WOLFSSL_TI_SA2UL_DEVID,
                                       ti_sa2ul_CryptoDevCb, NULL);
}

#endif /* WOLFSSL_TI_AM64X_A53_INTEGRITY */
