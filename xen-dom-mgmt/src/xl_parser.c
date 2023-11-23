/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include <zephyr/logging/log.h>

#include <xl_parser.h>

LOG_MODULE_DECLARE(xl_parser);

enum BACKEND_TYPE {
	BACKEND_TYPE_UNDEFINED,
	BACKEND_TYPE_VIF,
	BACKEND_TYPE_PVBLOCK
};

static const char *VIF_PREFIX = "vif";
static const char *DISK_PREFIX = "disk";

static const char *KEY_BACKEND = "backend";
static const char *KEY_SCRIPT = "script";
static const char *KEY_MAC = "mac";
static const char *KEY_BRIDGE = "bridge";
static const char *KEY_IP = "ip";
static const char *KEY_VDEV = "vdev";
static const char *KEY_ACCESS = "access";
static const char *KEY_TARGET = "target";

typedef void (*key_value_func_t)(const char*, const char*, void*);

#define MAX_PROPERTY_STRING_SIZE 256

/*
 * pv_block
 * default: backendtype=phy format=raw script=/etc/xen/scripts/block
 * supported keys: backend, vdev, access, target, script
 * example: disk= [ 'backend=1, vdev=xvda, access=rw, target=/dev/mmcblk0p3' ]
 */
static void process_disk_key_value(const char *key, const char *value, void *vcfg)
{
	struct pv_block_configuration *cfg = (struct pv_block_configuration *)vcfg;

	cfg->configured = true;

	if (!strncmp(key, KEY_BACKEND, strlen(KEY_BACKEND))) {
		cfg->backend_domain_id = atoi(value);
	} else if (!strncmp(key, KEY_VDEV, strlen(KEY_VDEV))) {
		strncpy(cfg->vdev, value, INIT_XENSTORE_BUFF_SIZE);
	} else if (!strncmp(key, KEY_ACCESS, strlen(KEY_ACCESS))) {
		strncpy(cfg->access, value, INIT_XENSTORE_BUFF_SIZE);
	} else if (!strncmp(key, KEY_TARGET, strlen(KEY_TARGET))) {
		strncpy(cfg->target, value, INIT_XENSTORE_BUFF_SIZE);
	} else if (!strncmp(key, KEY_SCRIPT, strlen(KEY_SCRIPT))) {
		strncpy(cfg->script, value, INIT_XENSTORE_BUFF_SIZE);
	}
}

/*
 * pv_net
 * default: type=vif script=/etc/xen/scripts/vif-bridge
 * supported keys: backend, mac, bridge, ip, script
 * example:
 * vif=['backend=1,bridge=xenbr0,mac=08:00:27:ff:cb:ce,ip=172.44.0.2 255.255.255.0 172.44.0.1']
 */
static void process_vif_key_value(const char *key, const char *value, void *vcfg)
{
	struct pv_net_configuration *cfg = (struct pv_net_configuration *)vcfg;

	cfg->configured = true;

	if (!strncmp(key, KEY_BACKEND, strlen(KEY_BACKEND))) {
		cfg->backend_domain_id = atoi(value);
	} else if (!strncmp(key, KEY_SCRIPT, strlen(KEY_SCRIPT))) {
		strncpy(cfg->script, value, INIT_XENSTORE_BUFF_SIZE);
	} else if (!strncmp(key, KEY_MAC, strlen(KEY_MAC))) {
		strncpy(cfg->mac, value, INIT_XENSTORE_BUFF_SIZE);
	} else if (!strncmp(key, KEY_BRIDGE, strlen(KEY_BRIDGE))) {
		strncpy(cfg->bridge, value, INIT_XENSTORE_BUFF_SIZE);
	} else if (!strncmp(key, KEY_IP, strlen(KEY_IP))) {
		strncpy(cfg->ip, value, INIT_XENSTORE_BUFF_SIZE);
	}
}

static enum BACKEND_TYPE detect_backend_type(const char *str)
{
	if (!strncmp(str, VIF_PREFIX, strlen(VIF_PREFIX))) {
		return BACKEND_TYPE_VIF;
	} else if (!strncmp(str, DISK_PREFIX, strlen(DISK_PREFIX))) {
		return BACKEND_TYPE_PVBLOCK;
	}
	return BACKEND_TYPE_UNDEFINED;
}

static void *find_entry_and_set_defaults(enum BACKEND_TYPE bt, struct backend_configuration *cfg)
{
	int i = 0;

	if (bt == BACKEND_TYPE_VIF) {
		for (i = 0; i < MAX_PV_NET_DEVICES; i++) {
			if (!cfg->vifs[i].configured) {
				cfg->vifs[i].configured = true;
				strncpy(cfg->vifs[i].script, "/etc/xen/scripts/vif-bridge",
						INIT_XENSTORE_BUFF_SIZE);
				strncpy(cfg->vifs[i].type, "vif", INIT_XENSTORE_BUFF_SIZE);
				return &cfg->vifs[i];
			}
		}
	} else if (bt == BACKEND_TYPE_PVBLOCK) {
		for (i = 0; i < MAX_PV_BLOCK_DEVICES; i++) {
			if (!cfg->disks[i].configured) {
				cfg->disks[i].configured = true;
				strncpy(cfg->disks[i].backendtype, "phy", INIT_XENSTORE_BUFF_SIZE);
				strncpy(cfg->disks[i].format, "raw", INIT_XENSTORE_BUFF_SIZE);
				strncpy(cfg->disks[i].script, "/etc/xen/scripts/block",
						INIT_XENSTORE_BUFF_SIZE);
				return &cfg->disks[i];
			}
		}
	}

	return NULL;
}

static key_value_func_t find_func_by_type(enum BACKEND_TYPE bt)
{
	switch (bt) {
	case BACKEND_TYPE_VIF:
		return  &process_vif_key_value;
	case BACKEND_TYPE_PVBLOCK:
		return  &process_disk_key_value;
	case BACKEND_TYPE_UNDEFINED:
		return NULL;
	}
	return NULL;
}

static void parse_key_value(char *input, key_value_func_t kv_func, void *cfg)
{
	char *s, *equal_sign, *key, *value, *end;
	char *token = strtok_r(input, ",", &s);

	while (token != NULL) {
		equal_sign = strchr(token, '=');

		if (equal_sign != NULL) {
			*equal_sign = '\0';
			key = token;
			value = equal_sign + 1;

			while (*key == ' ' || *key == '\t') {
				key++;
			}
			end = value + strlen(value) - 1;

			while (end > value && (*end == ' ' || *end == '\t')) {
				*end = '\0';
				end--;
			}
			kv_func(key, value, cfg);
		}

		token = strtok_r(NULL, ",", &s);
	}
}

/* Parse one configuration like ['configuration1', 'configuration2' ... ] */
static const char *find_and_parse_next_device(const char *str, enum BACKEND_TYPE bt,
							struct backend_configuration *cfg)
{
	char entry[MAX_PROPERTY_STRING_SIZE] = {0};
	void *dev_desr = NULL;
	key_value_func_t kvfunc = NULL;
	const char *lq, *rq;
	int str_len = strnlen(str, MAX_PROPERTY_STRING_SIZE);

	/* Corrupted string */
	if (str_len == MAX_PROPERTY_STRING_SIZE)
		return NULL;

	/* Searching for left quote */
	lq = strchr(str, '\'');

	if (!lq || (lq && (lq - str >= str_len)))
		return NULL;

	/* Searching for right quote */
	rq = strchr(lq + 1, '\'');

	if (!rq || (rq - lq) > MAX_PROPERTY_STRING_SIZE)
		return NULL;

	strncpy(entry, lq + 1, rq - lq - 1);

	dev_desr = find_entry_and_set_defaults(bt, cfg);
	kvfunc = find_func_by_type(bt);

	if (!dev_desr || !kvfunc)
		return NULL;

	parse_key_value(entry, kvfunc, dev_desr);
	/* Return pointer to next character after right quote */
	return rq + 1;
}

int parse_one_record_and_fill_cfg(const char *str, struct backend_configuration *cfg)
{
	const char *dstr = str;
	enum BACKEND_TYPE bt;

	if (!str || !cfg)
		return -EINVAL;

	bt = detect_backend_type(dstr);

	if (bt == BACKEND_TYPE_UNDEFINED)
		return -EINVAL;

	while ((dstr = find_and_parse_next_device(dstr, bt, cfg)) != NULL) {
		dstr = strchr(dstr, ',');
		if (!dstr)
			return 0;
	}

	return 0;
}
