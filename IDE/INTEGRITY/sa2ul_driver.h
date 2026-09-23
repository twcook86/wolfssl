/* sa2ul_driver.h
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

#ifndef SA2UL_DRIVER_H
#define SA2UL_DRIVER_H

#include <stdint.h>
#include <INTEGRITY.h>

#include <driver/soc/jacinto7/j7_dma.h>

#include "sa2ul_iodevice.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This needs to be confirmed during bringup */
#define SA2UL_DMA_SUBTYPE_ID 2u

int sa2ul_driver_set_dma(volatile void *CpAceBase, J7DmaDev *DmaDev,
        Value TxChannelIdx, Value Rx1ChannelIdx, Value Rx2ChannelIdx);

int sa2ul_driver_aes(struct Sa2ulCtrl *Ctrl, MemoryRegion DataMr,
        struct Sa2ulData *Data);

int sa2ul_driver_sha(struct Sa2ulCtrl *Ctrl, MemoryRegion DataMr,
        struct Sa2ulData *Data);

#ifdef __cplusplus
}
#endif

#endif /* SA2UL_DRIVER_H */
