/* sa2ul_iodevice_server.c
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

/* Kernel-side IODevice exposing sa2ul_driver.c's AES and SHA engines
 * to Task AddressSpaces.
 */

#include <INTEGRITY.h>
#include <string.h>

#include "sa2ul_driver.h"
#include "sa2ul_iodevice.h"

#include "myproject_integrate.h"

static struct IODeviceVectorStruct Sa2ulDeviceVector;
static MemoryRegion gCtrlMr = NULLMemoryRegion;
static MemoryRegion gDataMr = NULLMemoryRegion;
static volatile struct Sa2ulCtrl *gCtrl = NULL;
static volatile struct Sa2ulData *gData = NULL;

static Error Sa2ulDeviceCreate(IODeviceVector TheIODeviceVector)
{
    (void)TheIODeviceVector;
    return Success;
}

static Error Sa2ulDeviceReadStatus(IODeviceVector TheIODeviceVector,
        Value StatusNumber, void *Buffer, Address Length)
{
    struct Sa2ulCtrl LocalCtrl;
    Error err;

    (void)TheIODeviceVector;
    (void)StatusNumber;
    (void)Buffer;
    (void)Length;

    if (gCtrl == NULL || gData == NULL) {
        return Failure;
    }

    /* Read the Task's request through a coherent copy */
    err = CopyFromMemoryRegionWithFlags(gCtrlMr,
            (ExtendedAddress)(uintptr_t)gCtrl,
            &LocalCtrl, sizeof(LocalCtrl), ACCESS_SRC_COHERENT);
    if (err != Success) {
        return Failure;
    }

    switch (LocalCtrl.op) {
    case SA2UL_OP_SHA1:
    case SA2UL_OP_SHA256:
    case SA2UL_OP_SHA512:
        (void)sa2ul_driver_sha(&LocalCtrl, gDataMr, (struct Sa2ulData *)gData);
        break;
    default:
        (void)sa2ul_driver_aes(&LocalCtrl, gDataMr, (struct Sa2ulData *)gData);
        break;
    }

    err = CopyToMemoryRegionWithFlags(gCtrlMr,
            (ExtendedAddress)(uintptr_t)gCtrl,
            &LocalCtrl, sizeof(LocalCtrl), ACCESS_DST_COHERENT);
    if (err != Success) {
        return Failure;
    }

    return Success;
}

void InitSa2ulDevice(void)
{
    Address VirtFirst, VirtLast;

    gCtrlMr = sa2ul_ctrl_phys;
    if (GetMemoryRegionAddresses(gCtrlMr, &VirtFirst, &VirtLast) != Success ||
            (VirtLast - VirtFirst + 1) < sizeof(struct Sa2ulCtrl)) {
        return;
    }
    gCtrl = (volatile struct Sa2ulCtrl *)VirtFirst;

    gDataMr = sa2ul_data_phys;
    if (GetMemoryRegionAddresses(gDataMr, &VirtFirst, &VirtLast) != Success ||
            (VirtLast - VirtFirst + 1) < sizeof(struct Sa2ulData)) {
        return;
    }
    gData = (volatile struct Sa2ulData *)VirtFirst;

    memset(&Sa2ulDeviceVector, 0, sizeof(Sa2ulDeviceVector));
    Sa2ulDeviceVector.Create     = Sa2ulDeviceCreate;
    Sa2ulDeviceVector.ReadStatus = Sa2ulDeviceReadStatus;

    RegisterIODeviceVector(&Sa2ulDeviceVector, SA2UL_IODEVICE_NAME);
}

typedef void (*voidfunc)();
voidfunc __ghsentry_bspuserinit_InitSa2ulDevice = InitSa2ulDevice;
