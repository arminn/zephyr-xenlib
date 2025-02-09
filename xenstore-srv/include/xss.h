/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright (c) 2023 EPAM Systems
 *
 */

#pragma once
#include <zephyr/xen/public/xen.h>

#ifdef __cplusplus
extern "C" {
#endif

enum xs_perm {
	XS_PERM_NONE = 0x0,
	XS_PERM_READ = 0x1,
	XS_PERM_WRITE = 0x2,
	XS_PERM_BOTH = XS_PERM_WRITE | XS_PERM_READ
};

/*
 * Read the value associated with a path.
 *
 * @param path Xenstore path
 * @param value pre-allocated buffer for Xenstore value
 * @param len size of pre-allocated buffer
 * @return 0 on success, a negative errno value on error.
 */
int xss_read(const char *path, char *value, size_t len);

/*
 * Associates a value with a path.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @return 0 on success, a negative errno value on error.
 */
int xss_write(const char *path, const char *value);

/*
 * Associates a value with a path and set read-write permissions for given domid.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @return 0 on success, a negative errno value on error.
 */
int xss_write_guest_domain_rw(const char *path, const char *value, uint32_t domid);

/*
 * Associates a value with a path and set read-only permissions for given domid.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @return 0 on success, a negative errno value on error.
 */
int xss_write_guest_domain_ro(const char *path, const char *value, uint32_t domid);

/*
 * Read path and parse it as an integer.
 *
 * @param path Xenstore path
 * @param value Returned int value
 * @return 0 on success, a negative errno value on error.
 */
int xss_read_integer(const char *path, int *value);

/*
 * Sets permissions for input path and domid.
 *
 * @param path Xenstore path
 * @param domid Domain ID
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xss_set_perm(const char *path, domid_t domid, enum xs_perm perm);

/*
 * Removes the value associated with a path.
 *
 * @param path Xenstore path
 * @return 0 on success, a negative errno value on error.
 */
int xss_rm(const char *path);

#ifdef __cplusplus
}
#endif
