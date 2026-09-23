/* sa2ul_driver.c
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

/* Kernel-linked AES + SHA/auth-hash driver for the AM64x SA2UL crypto
 * accelerator.
 *
 * This is not a completely fresh implementation. It is mostly a
 * port of TI's mcu_plus_sdk_am64x SA2UL driver.  Hooks to the SDK UDMA
 * engine were replaced by calls to the j7_dma api in the Integrity BSP.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include <INTEGRITY.h>

#include <driver/soc/jacinto7/j7_dma.h>
#include <driver/soc/jacinto7/j7_sci.h>

#include "sa2ul_driver.h"

/* CP_ACE base = 0x40900000 register space */
#define CP_ACE_MMR_EFUSE_EN_OFFSET           0x04u
#define CP_ACE_MMR_CMD_STATUS_OFFSET         0x08u
#define CP_ACE_UPDATES_ENGINE_ENABLE_OFFSET  0x1000u

#define CP_ACE_EFUSE_EN_ENABLE_BIT          0x1u
#define CP_ACE_ENCSS_EN_MASK                0x1u   /* bit 0 */
#define CP_ACE_AUTHSS_EN_MASK               0x2u   /* bit 1 */
#define CP_ACE_CTX_EN_MASK                  0x80u  /* bit 7 */
#define CP_ACE_CDMA_IN_EN_MASK              0x200u /* bit 9 */
#define CP_ACE_CDMA_OUT_EN_MASK             0x800u /* bit 11 */
#define SA2UL_ENGINE_MASK (CP_ACE_ENCSS_EN_MASK | CP_ACE_AUTHSS_EN_MASK | \
        CP_ACE_CTX_EN_MASK | CP_ACE_CDMA_IN_EN_MASK | CP_ACE_CDMA_OUT_EN_MASK)

static volatile uint8_t *gCpAceBase = NULL;
#define CPACE_REG32(off) (*(volatile uint32_t *)(gCpAceBase + (off)))

static int sa2ul_engine_enable(void)
{
    uint32_t efuse, reg;
    unsigned int timeout;

    efuse = CPACE_REG32(CP_ACE_MMR_EFUSE_EN_OFFSET);
    if ((efuse & CP_ACE_EFUSE_EN_ENABLE_BIT) == 0u) {
        printf("sa2ul_driver: engine not enabled by efuse (EFUSE_EN=0x%08lx)\n",
                (unsigned long)efuse);
        return -1;
    }

    reg = CPACE_REG32(CP_ACE_UPDATES_ENGINE_ENABLE_OFFSET);
    reg |= SA2UL_ENGINE_MASK;
    CPACE_REG32(CP_ACE_UPDATES_ENGINE_ENABLE_OFFSET) = reg;

    for (timeout = 0; timeout < 1000000u; timeout++) {
        if ((CPACE_REG32(CP_ACE_MMR_CMD_STATUS_OFFSET) & SA2UL_ENGINE_MASK)
                == SA2UL_ENGINE_MASK) {
            return 0;
        }
    }
    printf("sa2ul_driver: engine enable timed out (CMD_STATUS=0x%08lx)\n",
            (unsigned long)CPACE_REG32(CP_ACE_MMR_CMD_STATUS_OFFSET));
    return -1;
}

/* CPPI5 host-mode packet descriptor and SA2UL's own extension of it */
struct Cppi5HostDescr {
    uint32_t descInfo;
    uint32_t pktInfo1;
    uint32_t pktInfo2;
    uint32_t srcDstTag;
    uint64_t nextDescPtr;
    uint64_t bufPtr;
    uint32_t bufInfo1;
    uint32_t orgBufLen;
    uint64_t orgBufPtr;
};

struct Sa2ulExtendedPktInfo {
    uint32_t timestamp;
    uint32_t swWord0;
    uint32_t scptrL;
    uint32_t scptrH;
} __attribute__((__packed__));

struct Sa2ulPsDataTx {
    uint32_t inPsiInfo;
    uint32_t cmdLblHdr1;
    uint32_t cmdLblHdr2;
    uint32_t optionWords[52 / 4];
} __attribute__((__packed__));

struct Sa2ulPsDataRx {
    uint32_t trailerData[16];
} __attribute__((__packed__));

struct Sa2ulHostDescrTx {
    struct Cppi5HostDescr pd;
    struct Sa2ulExtendedPktInfo exPktInfo;
    struct Sa2ulPsDataTx psData;
} __attribute__((__packed__));

struct Sa2ulHostDescrRx {
    struct Cppi5HostDescr pd;
    struct Sa2ulExtendedPktInfo exPktInfo;
    struct Sa2ulPsDataRx psData;
} __attribute__((__packed__));

/* similar to CSL_* from the TI mcu plus sdk... */
#define FLD(val, shift, mask) ((((uint32_t)(val)) << (shift)) & (mask))
#define FEXT(reg, shift, mask) ((((uint32_t)(reg)) & (mask)) >> (shift))

#define UDMAP_CPPI5_PD_DESCINFO_DTYPE_SHIFT        27u
#define UDMAP_CPPI5_PD_DESCINFO_DTYPE_MASK         0x18000000u
#define CPPI5_PD_DESCINFO_DTYPE_VAL_HOST           2u
#define UDMAP_CPPI5_PD_DESCINFO_EINFO_SHIFT        26u
#define UDMAP_CPPI5_PD_DESCINFO_EINFO_MASK         0x04000000u
#define CPPI5_PD_DESCINFO_EINFO_VAL_IS_PRESENT     1u
#define UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT       22u
#define UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK        0x03c00000u
#define UDMAP_CPPI5_PD_DESCINFO_PKTLEN_SHIFT       0u
#define UDMAP_CPPI5_PD_DESCINFO_PKTLEN_MASK        0x0003ffffu
#define PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_SHIFT      UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT
#define PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_MASK       UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK
#define PKTDMA_CPPI5_PD_DESCINFO_PKTLEN_SHIFT      UDMAP_CPPI5_PD_DESCINFO_PKTLEN_SHIFT
#define PKTDMA_CPPI5_PD_DESCINFO_PKTLEN_MASK       UDMAP_CPPI5_PD_DESCINFO_PKTLEN_MASK

#define UDMAP_CPPI5_PD_PKTINFO1_FLOWID_SHIFT       0u
#define UDMAP_CPPI5_PD_PKTINFO1_FLOWID_MASK        0x0000ffffu
#define UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_SHIFT       19u
#define UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_MASK        0x00780000u

#define UDMAP_CPPI5_PD_PKTINFO2_RETQ_SHIFT         0u
#define UDMAP_CPPI5_PD_PKTINFO2_RETQ_MASK          0x0000ffffu

#define SA2UL_SWWORD0_BYP_CMD_LBL_LEN_SHIFT        31u
#define SA2UL_SWWORD0_BYP_CMD_LBL_LEN_MASK         0x80000000u
#define SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_SHIFT  30u
#define SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_MASK   0x40000000u
#define SA2UL_SWWORD0_ENGINE_ID_SHIFT              25u
#define SA2UL_SWWORD0_ENGINE_ID_MASK               0x3e000000u
#define SA2UL_SWWORD0_CMD_LBL_PRESENT_SHIFT        24u
#define SA2UL_SWWORD0_CMD_LBL_PRESENT_MASK         0x1000000u
#define SA2UL_SWWORD0_CMD_LBL_OFFSET_SHIFT         20u
#define SA2UL_SWWORD0_CMD_LBL_OFFSET_MASK          0xf00000u
#define SA2UL_SWWORD0_FRAGMENT_SHIFT               19u
#define SA2UL_SWWORD0_FRAGMENT_MASK                0x80000u
#define SA2UL_SWWORD0_TEARDOWN_SHIFT               17u
#define SA2UL_SWWORD0_TEARDOWN_MASK                0x20000u
#define SA2UL_SWWORD0_EVICT_SHIFT                  16u
#define SA2UL_SWWORD0_EVICT_MASK                   0x10000u
#define SA2UL_SWWORD0_SCID_SHIFT                   0u
#define SA2UL_SWWORD0_SCID_MASK                    0xffffu

#define SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_SHIFT  24u
#define SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_MASK   0xff000000u

#define SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_SHIFT 16u
#define SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_MASK  0xffff0000u

#define SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_SHIFT 0u
#define SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_MASK  0xffffu
#define SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_SHIFT       16u
#define SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_MASK        0xff0000u
#define SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_SHIFT 24u
#define SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_MASK  0xff000000u

#define SA2UL_SCCTL1_OWNER_SHIFT                   31u
#define SA2UL_SCCTL1_OWNER_MASK                    0x80000000u
#define SA2UL_SCCTL1_EVICT_DONE_SHIFT               30u
#define SA2UL_SCCTL1_EVICT_DONE_MASK                0x40000000u
#define SA2UL_SCCTL1_FETCH_EVICT_CONTROL_SHIFT      16u
#define SA2UL_SCCTL1_FETCH_EVICT_CONTROL_MASK       0xff0000u

#define SA2UL_SCCTL2_PRIVID_SHIFT                  16u
#define SA2UL_SCCTL2_PRIVID_MASK                   0xff0000u
#define SA2UL_SCCTL2_PRIV_SHIFT                    8u
#define SA2UL_SCCTL2_PRIV_MASK                     0x300u
#define SA2UL_SCCTL2_SECURE_SHIFT                  0u
#define SA2UL_SCCTL2_SECURE_MASK                   0x1u

#define SA2UL_AUTHCTX1_MODESEL_SHIFT                31u
#define SA2UL_AUTHCTX1_MODESEL_MASK                 0x80000000u
#define SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_SHIFT 24u
#define SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_MASK  0x1f000000u
#define SA2UL_AUTHCTX1_SW_CONTROL_SHIFT             16u
#define SA2UL_AUTHCTX1_SW_CONTROL_MASK              0xff0000u

#define SA2UL_ENCRCTL_MODESEL_SHIFT                31u
#define SA2UL_ENCRCTL_MODESEL_MASK                 0x80000000u
#define SA2UL_ENCRCTL_USE_DKEK_SHIFT                30u
#define SA2UL_ENCRCTL_USE_DKEK_MASK                 0x40000000u
#define SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_SHIFT  24u
#define SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_MASK   0x1f000000u
#define SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_SHIFT     23u
#define SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_MASK      0x800000u
#define SA2UL_ENCRCTL_TRAILER_AT_END_SHIFT          22u
#define SA2UL_ENCRCTL_TRAILER_AT_END_MASK           0x400000u
#define SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_SHIFT 21u
#define SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_MASK  0x200000u
#define SA2UL_ENCRCTL_ENCRYPT_DECRYPT_SHIFT         20u
#define SA2UL_ENCRCTL_ENCRYPT_DECRYPT_MASK          0x100000u
#define SA2UL_ENCRCTL_BLK_SIZE_SHIFT                16u
#define SA2UL_ENCRCTL_BLK_SIZE_MASK                 0x70000u
#define SA2UL_ENCRCTL_SOP_OFFSET_SHIFT              8u
#define SA2UL_ENCRCTL_SOP_OFFSET_MASK               0xF00u
#define SA2UL_ENCRCTL_MIDDLE_OFFSET_SHIFT           4u
#define SA2UL_ENCRCTL_MIDDLE_OFFSET_MASK            0xF0u
#define SA2UL_ENCRCTL_EOP_OFFSET_SHIFT              0u
#define SA2UL_ENCRCTL_EOP_OFFSET_MASK               0xFu

#define SA2UL_ENGINE_CODE_ENCRYPTION_MODULE_P1     2u
#define SA2UL_ENGINE_CODE_AUTHENTICATION_MODULE_P1 4u
#define SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT      20u
#define SA2UL_OP_ENC                0x01u
#define SA2UL_OP_AUTH               0x02u
#define SA2UL_ENC_ALG_AES           0x0u
#define SA2UL_ENC_DIR_ENCRYPT       0x0u
#define SA2UL_ENC_DIR_DECRYPT       0x1u
#define SA2UL_ENC_MODE_ECB          0x0u
#define SA2UL_ENC_MODE_CBC          0x1u
#define SA2UL_ENC_MODE_GCM          0x2u
#define SA2UL_ENC_KEYSIZE_128       0x0u
#define SA2UL_ENC_KEYSIZE_256       0x2u
#define SA2UL_ENC_KEYSIZE_BITS(k) (128u + (64u * (k)))

#define SA2UL_MAX_KEY_SIZE_BYTES    32u
#define SA2UL_MAX_IV_SIZE_BYTES     16u
#define SA2UL_MAX_IV_SIZE_BYTES_GCM 12u
#define SA2UL_MAX_AAD_SIZE_BYTES    16u
#define SA2UL_GHASH_LENGTH_BYTES    16u
#define SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES 16u
#define SA2UL_CACHELINE_ALIGNMENT   16u
#define SA2UL_MAX_INPUT_LENGTH_ENC  0xFFFFu
#define SA2UL_PSIL_DST_THREAD_OFFSET 0x8000u

#define SA2UL_HASH_ALG_SHA1         0x12u
#define SA2UL_HASH_ALG_SHA2_256     0x14u
#define SA2UL_HASH_ALG_SHA2_512     0x16u
#define SA2UL_MAX_HASH_SIZE_BYTES   64u
#define SA2UL_MAX_INPUT_LENGTH_AUTH 0x3FFFFFu

/* bit 4 clear means HMAC, set means plain hash */
#define SA2UL_IS_HMAC(alg) (((alg) & 0x10u) == 0u)

/* indexed by hashAlg & 7u...
 *  SHA1=0x12->2, SHA2_256=0x14->4, SHA2_512=0x16->6
 *  (indices 0/1/3/5/7 are not supported by this port and are never reached) */
static const uint32_t gSa2ulHashSizeBytes[8] = {
    0u, 16u, 20u, 28u, 32u, 48u, 64u, 0u
};

/* This driver's own AES-only view of TI's SA2UL_ContextParams */
struct Sa2ulAesParams {
    uint8_t  encDirection;
    uint8_t  encMode;
    uint8_t  key[SA2UL_MAX_KEY_SIZE_BYTES];
    uint8_t  encKeySize;
    uint32_t inputLen;
    uint8_t  iv[SA2UL_MAX_IV_SIZE_BYTES];
    uint8_t  aad[SA2UL_MAX_AAD_SIZE_BYTES];
    uint8_t  ghash[SA2UL_GHASH_LENGTH_BYTES];
    uint32_t aadLen;
};

/* ctx for aes */
struct Sa2ulSecCtxEnc {
    uint32_t encrCtl;
    uint32_t modeCtrlInstrs[6];
    uint32_t hwCtrlWord;
    uint32_t encKeyValue[8];
    uint32_t encAux1[8];
    uint32_t encAux2[4];
    uint32_t encAux3[4];
    uint32_t encAux4[4];
    uint8_t  preCryptoData[15];
};

/* ctx for sha */
struct Sa2ulSecCtxAuth {
    uint32_t authCtx1;
    uint32_t reserved0;
    uint32_t authenticationLengthHi;
    uint32_t authenticationLengthLo;
    uint32_t reserved1[4];
    uint32_t authenticationKeyValueL[8];
    uint32_t oPadL[8];
    uint32_t authenticationKeyValueH[8];
    uint32_t oPadH[8];
};

struct Sa2ulScctl {
    uint32_t scctl1;
    uint32_t scctl2;
    uint32_t scptrH;
    uint32_t scptrL;
};

struct Sa2ulSecCtx {
    struct Sa2ulScctl scctl;
    uint32_t unused[12];
    union {
        struct Sa2ulSecCtxAuth auth;
        struct Sa2ulSecCtxEnc  enc;
    } u;
};

/* This is simplified vs the SDK's SA2UL_ContextObject.
 * Covers both ops this port supports (SA2UL_OP_ENC/SA2UL_OP_AUTH) */
struct Sa2ulContext {
    struct Sa2ulSecCtx     secCtx;
    uint8_t                secCtxId;
    uint8_t                opType;
    uint8_t                hashAlg;
    struct Sa2ulAesParams  prms;
    uint32_t               totalLengthInBytes;
};

/* Mode-control-engine microcode tables
 *  References in the TI SDK sa2ul.c: gSa2ulMceAes*[], gSa2ulMceDataArray[],
 *  MCE_PACK2(), SA2UL_EncBlksizeEncoded[], SA2UL_getMceIndex()) */

#define MCE_PACK2(op1, f21, f11, f01, op2, f22, f12, f02) \
        ((op1) << 4) | ((f21) << 2) | ((f11) >> 1), \
        (((f11) & 1) << 7) | ((f01) << 4) | (op2), \
        ((f22) << 6) | ((f12) << 3) | (f02)

static const uint8_t SA2UL_EncBlksizeEncoded[2] = { 1u, 0u }; /* [SA2UL_ENC_ALG_AES]=1 */

static const uint8_t gSa2ulMceAes256CbcEncr[] = {
    MCE_PACK2(1, 0, 1, 0,   8, 2, 1, 0),
    MCE_PACK2(10, 2, 4, 4,  11, 1, 7, 6)
};
static const uint8_t gSa2ulMceAes256CbcDecr[] = {
    MCE_PACK2(8, 2, 1, 0,   10, 3, 1, 2),
    MCE_PACK2(9, 2, 1, 7,   4, 1, 0, 0),
    MCE_PACK2(12, 0, 0, 0,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes256Ecb[] = {
    MCE_PACK2(8, 2, 1, 0,   10, 0, 0, 4),
    MCE_PACK2(11, 1, 7, 1,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes128CbcDecr[] = {
    MCE_PACK2(8, 0, 1, 0,   10, 3, 1, 2),
    MCE_PACK2(9, 2, 1, 7,   4, 1, 0, 0),
    MCE_PACK2(12, 0, 0, 0,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes128CbcEncr[] = {
    MCE_PACK2(1, 0, 1, 0,   8, 0, 1, 0),
    MCE_PACK2(10, 2, 4, 4,  11, 1, 7, 6)
};
static const uint8_t gSa2ulMceAes128Ecb[] = {
    MCE_PACK2(8, 0, 1, 0,   10, 0, 0, 4),
    MCE_PACK2(11, 1, 7, 1,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes256GcmEncr[] = {
 0x88, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x8a, 0x90, 0x71, 0x41,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes256GcmDecr[] = {
 0x88, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x8a, 0x14, 0x19, 0x07,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes128GcmEncr[] = {
 0x80, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x0a, 0x90, 0x71, 0x41,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes128GcmDecr[] = {
 0x80, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x0a, 0x14, 0x19, 0x07,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};

struct Sa2ulMceData {
    uint8_t sopOffset, middleOffset, eopOffset;
    uint8_t nMCInstrs;
    const uint8_t *mcInstrs;
};

enum {
    MCE_IDX_AES_256_ECB = 0, MCE_IDX_AES_256_CBC_ENCRYPT, MCE_IDX_AES_256_CBC_DECRYPT,
    MCE_IDX_AES_128_ECB, MCE_IDX_AES_128_CBC_ENCRYPT, MCE_IDX_AES_128_CBC_DECRYPT,
    MCE_IDX_AES_256_GCM_ENCRYPT, MCE_IDX_AES_256_GCM_DECRYPT,
    MCE_IDX_AES_128_GCM_ENCRYPT, MCE_IDX_AES_128_GCM_DECRYPT,
    MCE_IDX_COUNT
};

static const struct Sa2ulMceData gSa2ulMceDataArray[MCE_IDX_COUNT] = {
    { 0, 0, 0, sizeof(gSa2ulMceAes256Ecb),      gSa2ulMceAes256Ecb },
    { 0, 0, 0, sizeof(gSa2ulMceAes256CbcEncr),  gSa2ulMceAes256CbcEncr },
    { 0, 0, 0, sizeof(gSa2ulMceAes256CbcDecr),  gSa2ulMceAes256CbcDecr },
    { 0, 0, 0, sizeof(gSa2ulMceAes128Ecb),      gSa2ulMceAes128Ecb },
    { 0, 0, 0, sizeof(gSa2ulMceAes128CbcEncr),  gSa2ulMceAes128CbcEncr },
    { 0, 0, 0, sizeof(gSa2ulMceAes128CbcDecr),  gSa2ulMceAes128CbcDecr },
    { 0, 4, 4, sizeof(gSa2ulMceAes256GcmEncr),  gSa2ulMceAes256GcmEncr },
    { 0, 4, 4, sizeof(gSa2ulMceAes256GcmDecr),  gSa2ulMceAes256GcmDecr },
    { 0, 4, 4, sizeof(gSa2ulMceAes128GcmEncr),  gSa2ulMceAes128GcmEncr },
    { 0, 4, 4, sizeof(gSa2ulMceAes128GcmDecr),  gSa2ulMceAes128GcmDecr }
};

/* SA2UL_getMceIndex(), same logic */
static int sa2ul_get_mce_index(const struct Sa2ulAesParams *P, uint8_t *aesKeyInvFlag)
{
    *aesKeyInvFlag = 0;
    if (P->encKeySize == SA2UL_ENC_KEYSIZE_256) {
        if (P->encMode == SA2UL_ENC_MODE_ECB) {
            if (P->encDirection == SA2UL_ENC_DIR_DECRYPT) *aesKeyInvFlag = 1;
            return MCE_IDX_AES_256_ECB;
        } else if (P->encMode == SA2UL_ENC_MODE_CBC) {
            if (P->encDirection == SA2UL_ENC_DIR_ENCRYPT) return MCE_IDX_AES_256_CBC_ENCRYPT;
            *aesKeyInvFlag = 1;
            return MCE_IDX_AES_256_CBC_DECRYPT;
        } else if (P->encMode == SA2UL_ENC_MODE_GCM) {
            return (P->encDirection == SA2UL_ENC_DIR_ENCRYPT) ?
                    MCE_IDX_AES_256_GCM_ENCRYPT : MCE_IDX_AES_256_GCM_DECRYPT;
        }
    } else { /* 128 */
        if (P->encMode == SA2UL_ENC_MODE_ECB) {
            if (P->encDirection == SA2UL_ENC_DIR_DECRYPT) *aesKeyInvFlag = 1;
            return MCE_IDX_AES_128_ECB;
        } else if (P->encMode == SA2UL_ENC_MODE_CBC) {
            if (P->encDirection == SA2UL_ENC_DIR_ENCRYPT) return MCE_IDX_AES_128_CBC_ENCRYPT;
            *aesKeyInvFlag = 1;
            return MCE_IDX_AES_128_CBC_DECRYPT;
        } else if (P->encMode == SA2UL_ENC_MODE_GCM) {
            return (P->encDirection == SA2UL_ENC_DIR_ENCRYPT) ?
                    MCE_IDX_AES_128_GCM_ENCRYPT : MCE_IDX_AES_128_GCM_DECRYPT;
        }
    }
    return -1;
}

/* AES key expansion
 * SA2UL's hardware needs the *inverse* key schedule preloaded for ECB/CBC
 * decryption (not for GCM -- GCM only ever runs AES forward encryption) */
static const uint32_t gSa2ulAesTe4[256] = {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U
};

static const uint32_t gSa2ulAesRcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

static int32_t sa2ul_aes_key_expand_enc(uint32_t *rk, uint32_t *cipherKey, int32_t keyBits)
{
    int32_t i = 0;
    uint32_t temp;
    const uint32_t *Te4 = gSa2ulAesTe4;

    rk[0] = cipherKey[0]; rk[1] = cipherKey[1];
    rk[2] = cipherKey[2]; rk[3] = cipherKey[3];

    if (keyBits == 128) {
        for (;;) {
            temp = rk[3];
            rk[4] = rk[0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                gSa2ulAesRcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) return 10;
            rk += 4;
        }
    }

    rk[4] = cipherKey[4]; rk[5] = cipherKey[5];
    /* This driver only ever calls with 128 or 256 -- 192 omitted
     * (matches AES-192 being unsupported by this hardware/port, see
     * check_aes_keylength() in wolfcrypt/src/port/ti/ti-sa2ul_port.c). */

    rk[6] = cipherKey[6]; rk[7] = cipherKey[7];
    if (keyBits == 256) {
        for (;;) {
            temp = rk[7];
            rk[8] = rk[0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                gSa2ulAesRcon[i];
            rk[9]  = rk[1] ^ rk[8];
            rk[10] = rk[2] ^ rk[9];
            rk[11] = rk[3] ^ rk[10];
            if (++i == 7) return 14;
            temp = rk[11];
            rk[12] = rk[4] ^
                (Te4[(temp >> 24)       ] & 0xff000000) ^
                (Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
                (Te4[(temp >>  8) & 0xff] & 0x0000ff00) ^
                (Te4[(temp      ) & 0xff] & 0x000000ff);
            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];
            rk += 8;
        }
    }
    return 0;
}

static void sa2ul_aes_inv_key(uint32_t *invKey, uint32_t *cipherKey, int32_t keyBits)
{
    uint32_t roundKey[60];
    uint32_t *rk = &roundKey[0];
    uint32_t *pInvRK = &roundKey[40];
    int32_t keySize = keyBits >> 5;

    if (keyBits == 128) {
        sa2ul_aes_key_expand_enc(rk, cipherKey, 128);
    }
    if (keyBits == 256) {
        sa2ul_aes_key_expand_enc(rk, cipherKey, 256);
        pInvRK = &roundKey[52];
    }
    memcpy(invKey, pInvRK, (size_t)keySize * 4u);
}

static void sa2ul_u8_le_to_u32(uint32_t *dest, const uint8_t *src, uint32_t len)
{
    uint32_t i, t = 0;
    for (i = 0; i < len; i++) {
        t = (t << 8) | src[i];
        if ((i & 3) == 3) { *dest++ = t; t = 0; }
    }
    if ((i & 3) != 0) { *dest = t << ((4 - (i & 3)) << 3); }
}

static void sa2ul_u32_le_to_u8(uint8_t *dest, const uint32_t *src, uint32_t len)
{
    uint32_t i, t;
    for (i = 0; i < len; i += 4) {
        t = *src++;
        *dest++ = (uint8_t)(t >> 24); *dest++ = (uint8_t)(t >> 16);
        *dest++ = (uint8_t)(t >> 8);  *dest++ = (uint8_t)t;
    }
}

static void sa2ul_64b_endian_swap(uint32_t *dest, const uint32_t *src, uint32_t len)
{
    uint32_t tmp[4], *t;
    uint32_t i, j;
    for (i = 0; i < len; i += 16) {
        t = &tmp[0];
        for (j = 0; j < 4; j++) *t++ = *src++;
        for (j = 0; j < 4; j++) *dest++ = *--t;
    }
}

/* DMA/ring plumbing...
/* This all needs to be flushed out during bringup with the integrity bsp */

static J7DmaDev *gDmaDev = NULL;
static J7RingDev gTxRing, gRx1Ring, gRx2Ring;
static Value gTxRingId, gRx1RingId, gRx2RingId;

#define SA2UL_RING_ELEMS 4u
struct Sa2ulPool {
    uint64_t txRingMem[SA2UL_RING_ELEMS];
    uint64_t rx1RingMem[SA2UL_RING_ELEMS];
    uint64_t rx2RingMem[SA2UL_RING_ELEMS];
    struct Sa2ulHostDescrTx txDescr __attribute__((aligned(SA2UL_CACHELINE_ALIGNMENT)));
    struct Sa2ulHostDescrRx rxDescr __attribute__((aligned(SA2UL_CACHELINE_ALIGNMENT)));
    struct Sa2ulContext     ctx     __attribute__((aligned(SA2UL_CACHELINE_ALIGNMENT)));
};

static volatile struct Sa2ulPool *gPool = NULL;
static uint64_t gPoolPhys = 0;
static MemoryRegion gPoolMr = NULLMemoryRegion;


#include "myproject_integrate.h"

#define SA2UL_POOL_PHYS_ADDR 0x82002000ull  /* see myproject.int */
#define SA2UL_DATA_PHYS_ADDR 0x82004000ull

static uint64_t sa2ul_pool_member_phys(const volatile void *Member)
{
    uint64_t off = (uint64_t)(uintptr_t)Member - (uint64_t)(uintptr_t)gPool;
    return gPoolPhys + off;
}

int sa2ul_driver_set_dma(volatile void *CpAceBase, J7DmaDev *DmaDev,
        Value TxChannelIdx, Value Rx1ChannelIdx, Value Rx2ChannelIdx)
{
    Address VirtFirst, VirtLast;
    Error err;

    gCpAceBase = (volatile uint8_t *)CpAceBase;
    if (sa2ul_engine_enable() != 0) {
        printf("sa2ul_driver_set_dma: engine enable failed\n");
        return -1;
    }

    gPoolMr = sa2ul_pool_phys;
    err = GetMemoryRegionAddresses(gPoolMr, &VirtFirst, &VirtLast);
    if (err != Success || (VirtLast - VirtFirst + 1) < sizeof(struct Sa2ulPool)) {
        printf("sa2ul_driver_set_dma: pool region bad (err=%d)\n", (int)err);
        return -1;
    }
    gPool = (volatile struct Sa2ulPool *)VirtFirst;
    gPoolPhys = SA2UL_POOL_PHYS_ADDR;

    gDmaDev = DmaDev;

    /* Reserve one completion ring per channel and pair each channel's
     * PSI-L thread with SA2UL's own side (already resolved to a channel
     * index by the caller via J7Dma_DevTree_Node_GetChannelInfo() --
     * see sa2ul_devtree_driver.c). */
    {
        Value txCq, rx1Cq, rx2Cq, rFlowBase;

        if (J7RingAcc_ReserveTxCompletionQueue(gDmaDev, SA2UL_DMA_SUBTYPE_ID, &txCq) != Success ||
            J7RingAcc_ReserveRxCompletionQueue(gDmaDev, SA2UL_DMA_SUBTYPE_ID, &rx1Cq) != Success ||
            J7RingAcc_ReserveRxCompletionQueue(gDmaDev, SA2UL_DMA_SUBTYPE_ID, &rx2Cq) != Success) {
            printf("sa2ul_driver_set_dma: ring reservation failed\n");
            return -1;
        }

        if (J7Dma_ConfigureTxChannel(gDmaDev, TxChannelIdx, txCq,
                sizeof(struct Sa2ulHostDescrTx)) != Success) {
            printf("sa2ul_driver_set_dma: tx channel config failed\n");
            return -1;
        }

        if (J7Dma_AllocRFlowIDRange(gDmaDev, SA2UL_DMA_SUBTYPE_ID, &rFlowBase, 1) != Success) {
            printf("sa2ul_driver_set_dma: rflow alloc failed\n");
            return -1;
        }
        if (J7Dma_ConfigureRxChannel(gDmaDev, Rx1ChannelIdx, rFlowBase, 1,
                rx1Cq, rx1Cq, sizeof(struct Sa2ulHostDescrRx)) != Success) {
            printf("sa2ul_driver_set_dma: rx1 channel config failed\n");
            return -1;
        }
        if (J7Dma_ConfigureRxChannel(gDmaDev, Rx2ChannelIdx, rFlowBase, 1,
                rx2Cq, rx2Cq, sizeof(struct Sa2ulHostDescrRx)) != Success) {
            printf("sa2ul_driver_set_dma: rx2 channel config failed\n");
            return -1;
        }

        gTxRingId = txCq; gRx1RingId = rx1Cq; gRx2RingId = rx2Cq;

        if (J7RingAcc_CreateRingMemIODev(gDmaDev->RingAcc, gTxRingId,
                sizeof(uint64_t), SA2UL_RING_ELEMS,
                (Address)(uintptr_t)gPool->txRingMem, gTxRingId,
                "Sa2ulTxRing", 0, &gTxRing, TRUE) != Success ||
            J7RingAcc_CreateRingMemIODev(gDmaDev->RingAcc, gRx1RingId,
                sizeof(uint64_t), SA2UL_RING_ELEMS,
                (Address)(uintptr_t)gPool->rx1RingMem, gRx1RingId,
                "Sa2ulRx1Ring", 0, &gRx1Ring, TRUE) != Success ||
            J7RingAcc_CreateRingMemIODev(gDmaDev->RingAcc, gRx2RingId,
                sizeof(uint64_t), SA2UL_RING_ELEMS,
                (Address)(uintptr_t)gPool->rx2RingMem, gRx2RingId,
                "Sa2ulRx2Ring", 0, &gRx2Ring, TRUE) != Success) {
            printf("sa2ul_driver_set_dma: ring mem iodev creation failed\n");
            return -1;
        }
    }

    return 0;
}

/* Similar to the SDK's SA2UL_contextAlloc(), but just for aes */
static int sa2ul_context_alloc(volatile struct Sa2ulContext *ctxObj,
        const struct Sa2ulAesParams *ctxPrms)
{
    struct Sa2ulSecCtx sc;
    int32_t mcDataIndex;
    uint8_t aesKeyInvFlag;
    uint64_t authLen, aadLen;

    memset((void *)&sc, 0, sizeof(sc));
    memcpy((void *)&ctxObj->prms, ctxPrms, sizeof(*ctxPrms));
    ctxObj->totalLengthInBytes = ctxPrms->inputLen;
    ctxObj->opType = SA2UL_OP_ENC;

    authLen = ((uint64_t)ctxPrms->inputLen) << 3;

    mcDataIndex = sa2ul_get_mce_index(ctxPrms, &aesKeyInvFlag);
    if (mcDataIndex < 0) {
        return -1;
    }

    sc.u.enc.encrCtl =
        FLD(0u, SA2UL_ENCRCTL_MODESEL_SHIFT, SA2UL_ENCRCTL_MODESEL_MASK) |
        FLD(0u, SA2UL_ENCRCTL_USE_DKEK_SHIFT, SA2UL_ENCRCTL_USE_DKEK_MASK) |
        FLD(SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT, SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_SHIFT, SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_MASK) |
        FLD(0u, SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_SHIFT, SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_MASK) |
        FLD(0u, SA2UL_ENCRCTL_TRAILER_AT_END_SHIFT, SA2UL_ENCRCTL_TRAILER_AT_END_MASK) |
        FLD(1u, SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_SHIFT, SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_MASK) |
        FLD(0u, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_SHIFT, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_MASK) |
        FLD(SA2UL_EncBlksizeEncoded[SA2UL_ENC_ALG_AES], SA2UL_ENCRCTL_BLK_SIZE_SHIFT, SA2UL_ENCRCTL_BLK_SIZE_MASK) |
        FLD(gSa2ulMceDataArray[mcDataIndex].sopOffset, SA2UL_ENCRCTL_SOP_OFFSET_SHIFT, SA2UL_ENCRCTL_SOP_OFFSET_MASK) |
        FLD(gSa2ulMceDataArray[mcDataIndex].middleOffset, SA2UL_ENCRCTL_MIDDLE_OFFSET_SHIFT, SA2UL_ENCRCTL_MIDDLE_OFFSET_MASK) |
        FLD(gSa2ulMceDataArray[mcDataIndex].eopOffset, SA2UL_ENCRCTL_EOP_OFFSET_SHIFT, SA2UL_ENCRCTL_EOP_OFFSET_MASK);

    if (ctxPrms->encMode == SA2UL_ENC_MODE_GCM) {
        sc.u.enc.encrCtl |= FLD(1u, SA2UL_ENCRCTL_TRAILER_AT_END_SHIFT, SA2UL_ENCRCTL_TRAILER_AT_END_MASK);
    } else {
        sc.u.enc.encrCtl |= FLD(ctxPrms->encDirection, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_SHIFT, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_MASK);
    }

    sa2ul_u8_le_to_u32(sc.u.enc.modeCtrlInstrs, gSa2ulMceDataArray[mcDataIndex].mcInstrs,
            gSa2ulMceDataArray[mcDataIndex].nMCInstrs);
    sc.u.enc.hwCtrlWord = 0;

    sa2ul_u8_le_to_u32(sc.u.enc.encKeyValue, ctxPrms->key, SA2UL_MAX_KEY_SIZE_BYTES);
    if (aesKeyInvFlag) {
        sa2ul_aes_inv_key(sc.u.enc.encKeyValue, sc.u.enc.encKeyValue,
                SA2UL_ENC_KEYSIZE_BITS(ctxPrms->encKeySize));
    }

    if (ctxPrms->encMode == SA2UL_ENC_MODE_GCM) {
        sa2ul_u8_le_to_u32(sc.u.enc.encAux3, ctxPrms->iv, SA2UL_MAX_IV_SIZE_BYTES_GCM);
        sc.u.enc.encAux3[SA2UL_MAX_IV_SIZE_BYTES_GCM / 4u] = 0x1u;
        sa2ul_u8_le_to_u32(sc.u.enc.encAux1, ctxPrms->ghash, SA2UL_GHASH_LENGTH_BYTES);
        sa2ul_u8_le_to_u32(sc.u.enc.encAux2, ctxPrms->aad, SA2UL_MAX_AAD_SIZE_BYTES);
        aadLen = ((uint64_t)ctxPrms->aadLen) << 3;
        sc.u.enc.encAux1[4] = (uint32_t)(aadLen >> 32);
        sc.u.enc.encAux1[5] = (uint32_t)(aadLen & 0xFFFFu);
        sc.u.enc.encAux1[6] = (uint32_t)(authLen >> 32);
        sc.u.enc.encAux1[7] = (uint32_t)(authLen & 0xFFFFu);
    } else {
        sa2ul_u8_le_to_u32(sc.u.enc.encAux3, ctxPrms->iv, SA2UL_MAX_IV_SIZE_BYTES);
    }

    sc.scctl.scctl1 =
        FLD(1u, SA2UL_SCCTL1_OWNER_SHIFT, SA2UL_SCCTL1_OWNER_MASK) |
        FLD(1u, SA2UL_SCCTL1_EVICT_DONE_SHIFT, SA2UL_SCCTL1_EVICT_DONE_MASK) |
        FLD(0x8Du, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_SHIFT, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_MASK);

    /* privId/priv/secure: 0/0/0 -- this driver runs entirely Non-secure,
     * unlike TI's SA2UL_Attrs (saAttrs->privId/priv/secure), which this
     * port doesn't carry forward (no equivalent config surface yet). */
    sc.scctl.scctl2 =
        FLD(0u, SA2UL_SCCTL2_PRIVID_SHIFT, SA2UL_SCCTL2_PRIVID_MASK) |
        FLD(0u, SA2UL_SCCTL2_PRIV_SHIFT, SA2UL_SCCTL2_PRIV_MASK) |
        FLD(0u, SA2UL_SCCTL2_SECURE_SHIFT, SA2UL_SCCTL2_SECURE_MASK);

    sa2ul_64b_endian_swap((uint32_t *)&ctxObj->secCtx, (uint32_t *)&sc, sizeof(sc));

    /* This should match TI's CacheP_wb()+CacheP_inv() pair */
    {
        Error err = CopyToMemoryRegionWithFlags(gPoolMr,
                sa2ul_pool_member_phys(&ctxObj->secCtx),
                (void *)&ctxObj->secCtx, sizeof(ctxObj->secCtx), ACCESS_DST_COHERENT);
        if (err != Success) return -1;
    }

    return 0;
}

/* Similar to the SDK's SA2UL_contextAlloc(), but just for sha */
static int sa2ul_context_alloc_auth(volatile struct Sa2ulContext *ctxObj,
        uint8_t hashAlg, uint32_t inputLen)
{
    struct Sa2ulSecCtx sc;
    uint64_t authLen;

    memset((void *)&sc, 0, sizeof(sc));
    ctxObj->totalLengthInBytes = inputLen;
    ctxObj->opType = SA2UL_OP_AUTH;
    ctxObj->hashAlg = hashAlg;

    authLen = ((uint64_t)inputLen) << 3;

    sc.u.auth.authCtx1 =
        FLD(0u, SA2UL_AUTHCTX1_MODESEL_SHIFT, SA2UL_AUTHCTX1_MODESEL_MASK) |
        FLD(SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT, SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_SHIFT, SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_MASK) |
        FLD(0x40u | hashAlg, SA2UL_AUTHCTX1_SW_CONTROL_SHIFT, SA2UL_AUTHCTX1_SW_CONTROL_MASK);

    /* Authentication length in bits for basic hash. */
    sc.u.auth.authenticationLengthLo = (uint32_t)authLen;
    sc.u.auth.authenticationLengthHi = (uint32_t)(authLen >> 32);

    /* FETCH_EVICT_CONTROL is 0x91 here, vs the ENC path's 0x8D above --
     * verbatim from sa2ul.c, not a typo. */
    sc.scctl.scctl1 =
        FLD(1u, SA2UL_SCCTL1_OWNER_SHIFT, SA2UL_SCCTL1_OWNER_MASK) |
        FLD(1u, SA2UL_SCCTL1_EVICT_DONE_SHIFT, SA2UL_SCCTL1_EVICT_DONE_MASK) |
        FLD(0x91u, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_SHIFT, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_MASK);

    /* privId/priv/secure: 0/0/0, same as the ENC path above (see its
     * identical comment). */
    sc.scctl.scctl2 =
        FLD(0u, SA2UL_SCCTL2_PRIVID_SHIFT, SA2UL_SCCTL2_PRIVID_MASK) |
        FLD(0u, SA2UL_SCCTL2_PRIV_SHIFT, SA2UL_SCCTL2_PRIV_MASK) |
        FLD(0u, SA2UL_SCCTL2_SECURE_SHIFT, SA2UL_SCCTL2_SECURE_MASK);

    sa2ul_64b_endian_swap((uint32_t *)&ctxObj->secCtx, (uint32_t *)&sc, sizeof(sc));

    {
        Error err = CopyToMemoryRegionWithFlags(gPoolMr,
                sa2ul_pool_member_phys(&ctxObj->secCtx),
                (void *)&ctxObj->secCtx, sizeof(ctxObj->secCtx), ACCESS_DST_COHERENT);
        if (err != Success) return -1;
    }

    return 0;
}

/* Push + poll-pop, combined into one synchronous call.
 * This may need to be reworked with interrupts, once the BSP source code
 * is available to us.
 */
static int sa2ul_context_process(volatile struct Sa2ulContext *ctxObj,
        uint64_t InPhys, uint32_t ilen, uint64_t OutPhys,
        uint8_t TrailerOut[SA2UL_MAX_HASH_SIZE_BYTES])
{
    volatile struct Sa2ulHostDescrTx *txDescr = &gPool->txDescr;
    volatile struct Sa2ulHostDescrRx *rxDescr = &gPool->rxDescr;
    J7RingDev *rxRing = (ilen >= 256u) ? &gRx2Ring : &gRx1Ring;
    Value rxRingId = (ilen >= 256u) ? gRx2RingId : gRx1RingId;
    uint32_t engineId = (ctxObj->opType == SA2UL_OP_AUTH) ?
            SA2UL_ENGINE_CODE_AUTHENTICATION_MODULE_P1 :
            SA2UL_ENGINE_CODE_ENCRYPTION_MODULE_P1;
    uint32_t trailerBytes = (ctxObj->opType == SA2UL_OP_AUTH) ?
            gSa2ulHashSizeBytes[ctxObj->hashAlg & 7u] :
            ((ctxObj->prms.encMode == SA2UL_ENC_MODE_GCM) ?
                    SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES : 0u);
    uint64_t phys;
    uint32_t reg, waited;

    memset((void *)txDescr, 0, sizeof(*txDescr));
    txDescr->pd.descInfo =
        FLD(CPPI5_PD_DESCINFO_DTYPE_VAL_HOST, UDMAP_CPPI5_PD_DESCINFO_DTYPE_SHIFT, UDMAP_CPPI5_PD_DESCINFO_DTYPE_MASK) |
        FLD(CPPI5_PD_DESCINFO_EINFO_VAL_IS_PRESENT, UDMAP_CPPI5_PD_DESCINFO_EINFO_SHIFT, UDMAP_CPPI5_PD_DESCINFO_EINFO_MASK) |
        FLD(12u >> 2, UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT, UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK) |
        FLD(ilen, UDMAP_CPPI5_PD_DESCINFO_PKTLEN_SHIFT, UDMAP_CPPI5_PD_DESCINFO_PKTLEN_MASK);
    txDescr->pd.pktInfo2 =
        FLD((uint32_t)gTxRingId, UDMAP_CPPI5_PD_PKTINFO2_RETQ_SHIFT, UDMAP_CPPI5_PD_PKTINFO2_RETQ_MASK);
    txDescr->exPktInfo.swWord0 =
        FLD(1u, SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_SHIFT, SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_MASK) |
        FLD(1u, SA2UL_SWWORD0_CMD_LBL_PRESENT_SHIFT, SA2UL_SWWORD0_CMD_LBL_PRESENT_MASK) |
        FLD(0u, SA2UL_SWWORD0_CMD_LBL_OFFSET_SHIFT, SA2UL_SWWORD0_CMD_LBL_OFFSET_MASK) |
        FLD(ctxObj->secCtxId, SA2UL_SWWORD0_SCID_SHIFT, SA2UL_SWWORD0_SCID_MASK) |
        FLD(engineId, SA2UL_SWWORD0_ENGINE_ID_SHIFT, SA2UL_SWWORD0_ENGINE_ID_MASK) |
        FLD(1u, SA2UL_SWWORD0_TEARDOWN_SHIFT, SA2UL_SWWORD0_TEARDOWN_MASK) |
        FLD(1u, SA2UL_SWWORD0_EVICT_SHIFT, SA2UL_SWWORD0_EVICT_MASK);
    txDescr->psData.cmdLblHdr1 =
        FLD(ilen, SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_SHIFT, SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_MASK) |
        FLD(8u, SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_SHIFT, SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_MASK) |
        FLD(SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT, SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_SHIFT, SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_MASK);

    phys = sa2ul_pool_member_phys(&ctxObj->secCtx);
    txDescr->exPktInfo.scptrL = (uint32_t)phys;
    txDescr->exPktInfo.scptrH = (uint32_t)(phys >> 32);
    if (trailerBytes != 0u) {
        txDescr->exPktInfo.scptrH |= FLD(trailerBytes,
                SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_SHIFT, SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_MASK);
    }
    txDescr->psData.inPsiInfo = FLD((uint32_t)rxRingId,
            SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_SHIFT, SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_MASK);

    txDescr->pd.bufPtr = InPhys;    txDescr->pd.bufInfo1 = ilen;
    txDescr->pd.orgBufPtr = InPhys; txDescr->pd.orgBufLen = ilen;

    memset((void *)rxDescr, 0, sizeof(*rxDescr));
    rxDescr->pd.descInfo = FLD(CPPI5_PD_DESCINFO_DTYPE_VAL_HOST,
            UDMAP_CPPI5_PD_DESCINFO_DTYPE_SHIFT, UDMAP_CPPI5_PD_DESCINFO_DTYPE_MASK);
    rxDescr->pd.bufPtr = OutPhys;    rxDescr->pd.bufInfo1 = ilen;
    rxDescr->pd.orgBufPtr = OutPhys; rxDescr->pd.orgBufLen = ilen;

    if (CopyToMemoryRegionWithFlags(gPoolMr, sa2ul_pool_member_phys(txDescr),
            (void *)txDescr, sizeof(*txDescr), ACCESS_DST_COHERENT) != Success ||
        CopyToMemoryRegionWithFlags(gPoolMr, sa2ul_pool_member_phys(rxDescr),
            (void *)rxDescr, sizeof(*rxDescr), ACCESS_DST_COHERENT) != Success) {
        return -1;
    }

    if (rxRing->Push(rxRing, TRUE, sa2ul_pool_member_phys(rxDescr)) != Success) {
        return -1;
    }
    if (gTxRing.Push(&gTxRing, TRUE, sa2ul_pool_member_phys(txDescr)) != Success) {
        return -1;
    }

    /* Poll the rx ring */
    for (waited = 0; waited < 1000000u; waited++) {
        if (rxRing->Pop(rxRing, TRUE, &phys) == Success && phys != 0u) {
            break;
        }
    }
    if (waited == 1000000u) {
        printf("sa2ul_driver: context_process timed out waiting on rx%s ring\n",
                (ilen >= 256u) ? "2" : "1");
        return -1;
    }

    if (CopyFromMemoryRegionWithFlags(gPoolMr, sa2ul_pool_member_phys(rxDescr),
            (void *)rxDescr, sizeof(*rxDescr), ACCESS_SRC_COHERENT) != Success) {
        return -1;
    }

    reg = FEXT(rxDescr->pd.pktInfo1, 19u, UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_MASK);
    if (reg != 0u) {
        printf("sa2ul_driver: SA2UL protocol-specific error flags 0x%lx\n", (unsigned long)reg);
        return -1;
    }

    if (trailerBytes != 0u) {
        uint32_t trailer[SA2UL_MAX_HASH_SIZE_BYTES / 4u];

        reg = FEXT(rxDescr->pd.descInfo, PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_SHIFT,
                PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_MASK);
        if ((reg << 2) != trailerBytes) {
            printf("sa2ul_driver: unexpected trailer length\n");
            return -1;
        }
        memcpy(trailer, (const void *)&rxDescr->psData.trailerData[0], trailerBytes);
        sa2ul_u32_le_to_u8(TrailerOut, trailer, trailerBytes);
    }

    /* Reclaim both descriptors back into their own rings for next call */
    (void)gTxRing.Pop(&gTxRing, TRUE, &phys);

    return 0;
}

/* Top-level entry point -- called by sa2ul_iodevice_server.c */
int sa2ul_driver_aes(struct Sa2ulCtrl *Ctrl, MemoryRegion DataMr,
        struct Sa2ulData *Data)
{
    struct Sa2ulAesParams prms;
    volatile struct Sa2ulContext *ctx = &gPool->ctx;
    uint64_t bufPhys;
    uint8_t gcmTag[SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES];

    if (gPool == NULL) {
        Ctrl->ret = SA2UL_DRIVER_NOT_READY;
        return Ctrl->ret;
    }
    if (Ctrl->sz > SA2UL_MAX_BUF || Ctrl->sz == 0u) {
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }
    if (Ctrl->keyBytes != 16u && Ctrl->keyBytes != 32u) {
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }

    memset(&prms, 0, sizeof(prms));
    prms.encKeySize = (Ctrl->keyBytes == 32u) ? SA2UL_ENC_KEYSIZE_256 : SA2UL_ENC_KEYSIZE_128;
    memcpy(prms.key, Ctrl->key, Ctrl->keyBytes);
    prms.inputLen = Ctrl->sz;

    switch (Ctrl->op) {
    case SA2UL_OP_AES_ECB_ENCRYPT:
    case SA2UL_OP_AES_ECB_DECRYPT:
        prms.encMode = SA2UL_ENC_MODE_ECB;
        prms.encDirection = (Ctrl->op == SA2UL_OP_AES_ECB_ENCRYPT) ?
                SA2UL_ENC_DIR_ENCRYPT : SA2UL_ENC_DIR_DECRYPT;
        break;
    case SA2UL_OP_AES_CBC_ENCRYPT:
    case SA2UL_OP_AES_CBC_DECRYPT:
        prms.encMode = SA2UL_ENC_MODE_CBC;
        prms.encDirection = (Ctrl->op == SA2UL_OP_AES_CBC_ENCRYPT) ?
                SA2UL_ENC_DIR_ENCRYPT : SA2UL_ENC_DIR_DECRYPT;
        memcpy(prms.iv, Ctrl->iv, SA2UL_MAX_IV_SIZE_BYTES);
        break;
    case SA2UL_OP_AES_GCM_ENCRYPT:
    case SA2UL_OP_AES_GCM_DECRYPT:
        prms.encMode = SA2UL_ENC_MODE_GCM;
        prms.encDirection = (Ctrl->op == SA2UL_OP_AES_GCM_ENCRYPT) ?
                SA2UL_ENC_DIR_ENCRYPT : SA2UL_ENC_DIR_DECRYPT;
        memcpy(prms.iv, Ctrl->iv, SA2UL_MAX_IV_SIZE_BYTES_GCM);
        if (Ctrl->aadSz > SA2UL_MAX_AAD_SIZE_BYTES) {
            Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
            return Ctrl->ret;
        }
        memcpy(prms.aad, Ctrl->aad, Ctrl->aadSz);
        prms.aadLen = Ctrl->aadSz;
        /* prms.ghash (GHASH(H)) is not computed here -- SA2UL derives it
         * from the AES key itself for a plain AES-GCM key schedule (no
         * ghash preload needed the way TI's ti_sa2ul_AesGcmEncrypt()
         * caller-side wrapper used to pass aes->gcm.H through from
         * wolfCrypt's own software GHASH setup). Left zeroed -- matches
         * this driver only supporting the GCM_NONCE_MID_SZ (12-byte IV)
         * case, which sa2ul_context_alloc() above always takes (see
         * ti-sa2ul_port.c: only ivSz==GCM_NONCE_MID_SZ is forwarded
         * here; anything else stays CRYPTOCB_UNAVAILABLE). */
        break;
    default:
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }

    if (sa2ul_context_alloc(ctx, &prms) != 0) {
        Ctrl->ret = SA2UL_DRIVER_HW_ERROR;
        return Ctrl->ret;
    }

    /* bufPhys is fixed (matches "sa2ul_data_phys"'s own Start in
     * proj/myproject.int) -- Data is this Kernel's own VA for that same
     * physical Object, same relationship gPool/gPoolPhys above has. The
     * Task already wrote its input into *its own* mapping of this same
     * page before triggering this call; write it back coherently here
     * (same idiom sa2ul_context_process() uses for the descriptors
     * themselves) so SA2UL's DMA engine -- a separate bus master this
     * core's ordinary cache isn't visible to -- sees it, not a stale
     * line still sitting dirty in this core's cache. */
    bufPhys = SA2UL_DATA_PHYS_ADDR;
    if (CopyToMemoryRegionWithFlags(DataMr, bufPhys, (void *)Data->buf,
            Ctrl->sz, ACCESS_DST_COHERENT) != Success) {
        Ctrl->ret = SA2UL_DRIVER_HW_ERROR;
        return Ctrl->ret;
    }

    if (sa2ul_context_process(ctx, bufPhys, Ctrl->sz, bufPhys, gcmTag) != 0) {
        Ctrl->ret = SA2UL_DRIVER_HW_ERROR;
        return Ctrl->ret;
    }

    /* The output bytes themselves are left for the Task's own coherent
     * read of its own mapping to pick up */
    if (Ctrl->op == SA2UL_OP_AES_GCM_ENCRYPT) {
        memcpy(Ctrl->tagOut, gcmTag, SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES);
    } else if (Ctrl->op == SA2UL_OP_AES_GCM_DECRYPT) {
        if (memcmp(Ctrl->tagIn, gcmTag, SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES) != 0) {
            Ctrl->ret = SA2UL_DRIVER_AUTH_FAILED;
            return Ctrl->ret;
        }
    }

    Ctrl->ret = SA2UL_DRIVER_OK;
    return Ctrl->ret;
}

/* SHA-1/SHA-256/SHA-512, one-shot */
int sa2ul_driver_sha(struct Sa2ulCtrl *Ctrl, MemoryRegion DataMr,
        struct Sa2ulData *Data)
{
    volatile struct Sa2ulContext *ctx = &gPool->ctx;
    uint64_t bufPhys;
    uint8_t digest[SA2UL_MAX_HASH_SIZE_BYTES];
    uint8_t hashAlg;

    if (gPool == NULL) {
        Ctrl->ret = SA2UL_DRIVER_NOT_READY;
        return Ctrl->ret;
    }
    if (Ctrl->sz > SA2UL_MAX_BUF || Ctrl->sz == 0u) {
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }

    switch (Ctrl->op) {
        case SA2UL_OP_SHA1:   hashAlg = SA2UL_HASH_ALG_SHA1;     break;
        case SA2UL_OP_SHA256: hashAlg = SA2UL_HASH_ALG_SHA2_256; break;
        case SA2UL_OP_SHA512: hashAlg = SA2UL_HASH_ALG_SHA2_512; break;
        default:
            Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
            return Ctrl->ret;
    }

    if (sa2ul_context_alloc_auth(ctx, hashAlg, Ctrl->sz) != 0) {
        Ctrl->ret = SA2UL_DRIVER_HW_ERROR;
        return Ctrl->ret;
    }

    /* coherent-write-then-process */
    bufPhys = SA2UL_DATA_PHYS_ADDR;
    if (CopyToMemoryRegionWithFlags(DataMr, bufPhys, (void *)Data->buf,
            Ctrl->sz, ACCESS_DST_COHERENT) != Success) {
        Ctrl->ret = SA2UL_DRIVER_HW_ERROR;
        return Ctrl->ret;
    }

    /* Same buffer for InPhys/OutPhys */
    if (sa2ul_context_process(ctx, bufPhys, Ctrl->sz, bufPhys, digest) != 0) {
        Ctrl->ret = SA2UL_DRIVER_HW_ERROR;
        return Ctrl->ret;
    }

    memcpy(Ctrl->digestOut, digest, gSa2ulHashSizeBytes[hashAlg & 7u]);

    Ctrl->ret = SA2UL_DRIVER_OK;
    return Ctrl->ret;
}
