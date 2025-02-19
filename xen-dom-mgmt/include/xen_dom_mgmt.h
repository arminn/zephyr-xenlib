/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XEN_DOM_MGMT_H
#define XENLIB_XEN_DOM_MGMT_H

#include <domain.h>

#ifdef __cplusplus
extern "C" {
#endif

int domain_create(struct xen_domain_cfg *domcfg, uint32_t domid);
int domain_destroy(uint32_t domid);
int domain_pause(uint32_t domid);
int domain_unpause(uint32_t domid);

#ifdef __cplusplus
}
#endif

#endif
