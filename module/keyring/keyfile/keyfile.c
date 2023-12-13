/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#include "spdk/keyring_module.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/util.h"

struct keyfile_key {
	char *path;
};

static int
keyfile_check_path(const char *path, int *size)
{
	struct stat st;
	int rc, errsv;

	rc = stat(path, &st);
	if (rc != 0) {
		errsv = errno;
		SPDK_ERRLOG("Invalid key: %s\n", spdk_strerror(errsv));
		return -errsv;
	}

	if (st.st_mode & 0177) {
		SPDK_ERRLOG("Invalid key permissions: %o\n", st.st_mode);
		return -EPERM;
	}

	if (size != NULL) {
		*size = st.st_size;
	}

	return 0;
}

static size_t
keyfile_get_ctx_size(void)
{
	return sizeof(struct keyfile_key);
}

static int
keyfile_get_key(struct spdk_key *key, void *buf, int len)
{
	struct keyfile_key *kkey = spdk_key_get_ctx(key);
	FILE *file;
	int rc, errsv, size;

	rc = keyfile_check_path(kkey->path, &size);
	if (rc != 0) {
		return rc;
	}

	if (size > len) {
		SPDK_ERRLOG("Invalid key '%s' size: %d > %d\n", spdk_key_get_name(key), size, len);
		return -ENOBUFS;
	}

	file = fopen(kkey->path, "r");
	if (!file) {
		errsv = errno;
		SPDK_ERRLOG("Could not open key '%s': %s\n", spdk_key_get_name(key),
			    spdk_strerror(errsv));
		return -errsv;
	}

	rc = (int)fread(buf, 1, size, file);
	if (rc != size) {
		SPDK_ERRLOG("Could not load key '%s'\n", spdk_key_get_name(key));
		rc = -EIO;
	}

	fclose(file);

	return rc;
}

static void
keyfile_remove_key(struct spdk_key *key)
{
	struct keyfile_key *kkey = spdk_key_get_ctx(key);

	free(kkey->path);
}

static const struct spdk_json_object_decoder keyfile_add_key_decoders[] = {
	{"keyfile_path", offsetof(struct keyfile_key, path), spdk_json_decode_string},
};

static int
keyfile_add_key(struct spdk_key *key, const struct spdk_json_val *opts)
{
	struct keyfile_key *kkey = spdk_key_get_ctx(key);
	int rc;

	rc = spdk_json_decode_object_relaxed(opts, keyfile_add_key_decoders,
					     SPDK_COUNTOF(keyfile_add_key_decoders), kkey);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to decode key '%s' parameters\n", spdk_key_get_name(key));
		return -EINVAL;
	}

	rc = keyfile_check_path(kkey->path, NULL);
	if (rc != 0) {
		free(kkey->path);
		return rc;
	}

	return 0;
}

static struct spdk_keyring_module g_keyfile = {
	.name = "keyfile",
	.add_key = keyfile_add_key,
	.remove_key = keyfile_remove_key,
	.get_key = keyfile_get_key,
	.get_ctx_size = keyfile_get_ctx_size,
};

SPDK_KEYRING_REGISTER_MODULE(keyfile, &g_keyfile);
