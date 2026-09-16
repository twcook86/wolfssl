/* ti-sa2ul_port.h
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

/* AM64x SA2UL crypto-callback (WOLF_CRYPTO_CB) hardware acceleration --
 * see ti-sa2ul_port.c's own header comment for the current (stubbed)
 * status. This port is staged in two parts: this half (the
 * WOLF_CRYPTO_CB plumbing -- device registration, per-algorithm dispatch
 * shape) does not depend on TI's mcu_plus_sdk at all yet, so it can be
 * ported and exercised (falling back to software for every operation)
 * before the mcu_plus_sdk SA2UL driver itself is ported into this tree.
 *
 * TRNG acceleration is intentionally NOT part of this file: this
 * project's entropy source is rng_driver.c (direct SA2UL/CP_ACE TRNG
 * register access from Kernel-linked code, exposed to Tasks as an
 * IODevice) -- see that file's own header comment. Do not define
 * CUSTOM_RAND_GENERATE_SEED/_BLOCK here; user_settings.h already points
 * it at integrity_rand_generate_seed().
 */

#ifndef _TI_SA2UL_PORT_H_
#define _TI_SA2UL_PORT_H_

#if defined(WOLFSSL_TI_AM64X)

#define WOLFSSL_TI_SA2UL_DEVID 8888
#define WC_USE_DEVID WOLFSSL_TI_SA2UL_DEVID

int ti_sa2ul_port_init(void);

#endif /* WOLFSSL_TI_AM64X */

#endif /* _TI_SA2UL_PORT_H_ */
