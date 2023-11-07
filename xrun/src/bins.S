/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/toolchain.h>

.section .data.img_u,"a"
GDATA(__img_u_start)
GDATA(__img_u_end)
__img_u_start:
.incbin	 "u.bin"
__img_u_end:
