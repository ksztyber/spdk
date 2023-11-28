/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#include "spdk/keyring.h"
#include "spdk/log.h"
#include "spdk/queue.h"

struct spdk_key {
	char			*name;
	int			refcnt;
	bool			removed;
	TAILQ_ENTRY(spdk_key)	tailq;
};

struct spdk_keyring {
	pthread_mutex_t		mutex;
	TAILQ_HEAD(, spdk_key)	keys;
};

static struct spdk_keyring g_keyring = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.keys = TAILQ_HEAD_INITIALIZER(g_keyring.keys),
};

static struct spdk_key *
keyring_find_key(const char *name)
{
	struct spdk_key *key;

	/* g_keyring.mutex must be held */
	TAILQ_FOREACH(key, &g_keyring.keys, tailq) {
		if (strcmp(key->name, name) == 0) {
			return key;
		}
	}

	return NULL;
}

static void
keyring_free_key(struct spdk_key *key)
{
	assert(key->refcnt == 0);

	free(key->name);
	free(key);
}

static void
keyring_put_key(struct spdk_key *key)
{
	assert(key->refcnt > 0);
	key->refcnt--;

	if (key->refcnt == 0) {
		assert(key->removed);
		keyring_free_key(key);
	}
}

int
spdk_keyring_add(const struct spdk_key_opts *opts)
{
	struct spdk_key *key;
	int rc = 0;

	pthread_mutex_lock(&g_keyring.mutex);
	if (keyring_find_key(opts->name) != NULL) {
		SPDK_ERRLOG("Key '%s' already exists\n", opts->name);
		rc = -EEXIST;
		goto out;
	}

	key = calloc(1, sizeof(*key));
	if (key == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	key->name = strdup(opts->name);
	if (key->name == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	key->refcnt = 1;
	TAILQ_INSERT_TAIL(&g_keyring.keys, key, tailq);
out:
	pthread_mutex_unlock(&g_keyring.mutex);
	if (rc != 0) {
		keyring_free_key(key);
	}

	return rc;
}

static void
keyring_remove_key(struct spdk_key *key)
{
	key->removed = true;
	TAILQ_REMOVE(&g_keyring.keys, key, tailq);
	keyring_put_key(key);
}

void
spdk_keyring_remove(const char *name)
{
	struct spdk_key *key;

	pthread_mutex_lock(&g_keyring.mutex);
	key = keyring_find_key(name);
	if (key == NULL) {
		SPDK_WARNLOG("Key '%s' does not exist\n", name);
		goto out;
	}

	keyring_remove_key(key);
out:
	pthread_mutex_unlock(&g_keyring.mutex);
}

struct spdk_key *
spdk_keyring_get(const char *name)
{
	struct spdk_key *key;

	pthread_mutex_lock(&g_keyring.mutex);
	key = keyring_find_key(name);
	if (key == NULL) {
		SPDK_ERRLOG("Key '%s' does not exist\n", name);
		goto out;
	}

	key->refcnt++;
out:
	pthread_mutex_unlock(&g_keyring.mutex);

	return key;
}

void
spdk_keyring_put(struct spdk_key *key)
{
	if (key == NULL) {
		return;
	}

	pthread_mutex_lock(&g_keyring.mutex);
	keyring_put_key(key);
	pthread_mutex_unlock(&g_keyring.mutex);
}

const char *
spdk_key_get_name(struct spdk_key *key)
{
	return key->name;
}

int
spdk_key_get_key(struct spdk_key *key, void *buf, int len)
{
	return -ENOTSUP;
}

int
spdk_keyring_init(void)
{
	return 0;
}

void
spdk_keyring_cleanup(void)
{
	struct spdk_key *key;

	while (!TAILQ_EMPTY(&g_keyring.keys)) {
		key = TAILQ_FIRST(&g_keyring.keys);
		if (key->refcnt > 1) {
			SPDK_WARNLOG("Key '%s' still has %d references\n", key->name, key->refcnt);
		}
		keyring_remove_key(key);
	}
}
