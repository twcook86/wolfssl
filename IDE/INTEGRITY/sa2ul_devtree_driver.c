/* sa2ul_devtree_driver.c
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

/* Device tree node driver for SA2UL's crypto engine -- companion to
 * rng_devtree_driver.c (same "ti,am64-sa2ul" parent node, same
 * DevTree_NodeDriver pattern), but resolves DMA channels instead of
 * just register windows.
 *
 * This board's DTS ("ti,am64-sa2ul" node, matching Linux's own
 * k3-am64-main.dtsi):
 *
 *   crypto: crypto@40900000 {
 *       compatible = "ti,am64-sa2ul";
 *       reg = <0x00 0x40900000 0x00 0x1200>;
 *       dmas = <&main_pktdma 0xc001 0>, <&main_pktdma 0x4002 0>,
 *              <&main_pktdma 0x4003 0>;
 *       dma-names = "tx", "rx1", "rx2";
 *       rng@40910000 { ... };
 *   };
 */

#include <bsp.h>
#include <INTEGRITY.h>
#include <asp_export.h>
#include <bsp_export.h>

#include <devtree.h>
#include <driver/soc/jacinto7/j7_dma_devtree.h>

#include "sa2ul_driver.h"

static Error Sa2ulNodeInit(DevTree_Node Node, const char *MatchName)
{
    Error err;
    Address CpAceAddr, CpAceSize;
    J7DmaDev *DmaDev;
    Value TxChannelIdx, Rx1ChannelIdx, Rx2ChannelIdx, Asel;

    (void)MatchName;

    err = DevTree_Node_GetRegAsKernel(Node, 0, &CpAceAddr, &CpAceSize);
    if (err != Success) {
        return err;
    }

    DmaDev = J7Dma_DevTree_Node_GetDevice(Node, "dmas", 0);
    if (DmaDev == NULL) {
        return Failure;
    }

    err = J7Dma_DevTree_Node_GetChannelInfo(DmaDev, Node, 0, &TxChannelIdx, &Asel);
    if (err != Success) {
        return err;
    }
    err = J7Dma_DevTree_Node_GetChannelInfo(DmaDev, Node, 1, &Rx1ChannelIdx, &Asel);
    if (err != Success) {
        return err;
    }
    err = J7Dma_DevTree_Node_GetChannelInfo(DmaDev, Node, 2, &Rx2ChannelIdx, &Asel);
    if (err != Success) {
        return err;
    }

    if (sa2ul_driver_set_dma((volatile void *)CpAceAddr, DmaDev,
            TxChannelIdx, Rx1ChannelIdx, Rx2ChannelIdx) != 0) {
        return Failure;
    }

    return Success;
}

DevTree_NodeDriver __ghsentry_devtree_node_driver_am64x_sa2ul_node = {
    .name = "AM64x SA2UL",
    .supported_types = (const char *[]){
        "ti,am64-sa2ul",
        NULL},
    .init = Sa2ulNodeInit,
};
