/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#include "keyring_internal.h"
#include "spdk/keyring.h"
#include "spdk/keyring_module.h"
#include "spdk/log.h"
#include "spdk/queue.h"
#include "spdk/string.h"

struct spdk_key {
	char				*name;
	int				refcnt;
	bool				removed;
	bool				probed;
	struct spdk_keyring_module	*module;
	TAILQ_ENTRY(spdk_key)		tailq;
};

struct spdk_keyring {
	pthread_mutex_t				mutex;
	TAILQ_HEAD(, spdk_keyring_module)	modules;
	TAILQ_HEAD(, spdk_key)			keys;
	TAILQ_HEAD(, spdk_key)			removed_keys;
};

static struct spdk_keyring g_keyring = {
	.keys = TAILQ_HEAD_INITIALIZER(g_keyring.keys),
	.removed_keys = TAILQ_HEAD_INITIALIZER(g_keyring.removed_keys),
	.modules = TAILQ_HEAD_INITIALIZER(g_keyring.modules),
};

static struct spdk_keyring_module *
keyring_find_module(const char *name)
{
	struct spdk_keyring_module *module;

	TAILQ_FOREACH(module, &g_keyring.modules, tailq) {
		if (strcmp(module->name, name) == 0) {
			return module;
		}
	}

	return NULL;
}

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

static int
keyring_put_key(struct spdk_key *key)
{
	assert(key->refcnt > 0);
	key->refcnt--;

	if (key->refcnt == 0) {
		assert(key->removed);
		TAILQ_REMOVE(&g_keyring.removed_keys, key, tailq);
		keyring_free_key(key);

		return 0;
	}

	return key->refcnt;
}

int
spdk_keyring_add(const struct spdk_key_opts *opts)
{
	struct spdk_key *key = NULL;
	struct spdk_keyring_module *module;
	int rc = 0;

	pthread_mutex_lock(&g_keyring.mutex);
	if (keyring_find_key(opts->name) != NULL) {
		SPDK_ERRLOG("Key '%s' already exists\n", opts->name);
		rc = -EEXIST;
		goto out;
	}

	module = keyring_find_module(opts->module);
	if (module == NULL) {
		SPDK_ERRLOG("Could not find module '%s'\n", opts->module);
		rc = -ENOENT;
		goto out;
	}

	key = calloc(1, sizeof(*key) + module->get_ctx_size());
	if (key == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	key->name = strdup(opts->name);
	if (key->name == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = module->add_key(key, opts->opts);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to add key '%s' to the keyring\n", opts->name);
		goto out;
	}

	key->module = module;
	key->refcnt = 1;
	TAILQ_INSERT_TAIL(&g_keyring.keys, key, tailq);
out:
	pthread_mutex_unlock(&g_keyring.mutex);
	if (rc != 0 && key != NULL) {
		keyring_free_key(key);
	}

	return rc;
}

static void
keyring_remove_key(struct spdk_key *key)
{
	assert(!key->removed);
	key->removed = true;
	key->module->remove_key(key);
	TAILQ_REMOVE(&g_keyring.keys, key, tailq);
	TAILQ_INSERT_TAIL(&g_keyring.removed_keys, key, tailq);
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

static struct spdk_key *
keyring_probe_key(const char *name)
{
	struct spdk_keyring_module *module;
	struct spdk_key *key = NULL;
	int rc;

	TAILQ_FOREACH(module, &g_keyring.modules, tailq) {
		if (module->probe_key == NULL) {
			continue;
		}

		rc = module->probe_key(name);
		if (rc == 0) {
			key = keyring_find_key(name);
			if (key == NULL) {
				SPDK_ERRLOG("Successfully probed key '%s' using module '%s', but "
					    "the key is unavailable\n", name, module->name);
				return NULL;
			}

			key->probed = true;
			break;
		} else if (rc != -ENOKEY) {
			/* The module is aware of the key but couldn't instantiate it */
			assert(keyring_find_key(name) == NULL);
			SPDK_ERRLOG("Failed to probe key '%s' using module '%s': %s\n",
				    name, module->name, spdk_strerror(-rc));
			break;
		}
	}

	return key;
}

struct spdk_key *
spdk_keyring_get(const char *name)
{
	struct spdk_key *key;

	pthread_mutex_lock(&g_keyring.mutex);
	key = keyring_find_key(name);
	if (key == NULL) {
		key = keyring_probe_key(name);
		if (key == NULL) {
			goto out;
		}
	}

	key->refcnt++;
out:
	pthread_mutex_unlock(&g_keyring.mutex);

	return key;
}

void
spdk_keyring_put(struct spdk_key *key)
{
	int refcnt;

	if (key == NULL) {
		return;
	}

	pthread_mutex_lock(&g_keyring.mutex);
	refcnt = keyring_put_key(key);
	if (refcnt == 1 && key->probed && !key->removed) {
		keyring_remove_key(key);
	}
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
	struct spdk_keyring_module *module = key->module;

	if (key->removed) {
		return -ENOKEY;
	}

	return module->get_key(key, buf, len);
}

void *
spdk_key_get_ctx(struct spdk_key *key)
{
	return key + 1;
}


struct spdk_keyring_module *
spdk_key_get_module(struct spdk_key *key)
{
	return key->module;
}

void
spdk_keyring_write_config(struct spdk_json_write_ctx *w)
{
	struct spdk_keyring_module *module;

	TAILQ_FOREACH(module, &g_keyring.modules, tailq) {
		if (module->write_config != NULL) {
			module->write_config(w);
		}
	}
}

void
spdk_keyring_for_each_key(void *ctx, void (*fn)(void *ctx, struct spdk_key *key), uint32_t flags)
{
	struct spdk_key *key, *tmp;

	pthread_mutex_lock(&g_keyring.mutex);
	TAILQ_FOREACH_SAFE(key, &g_keyring.keys, tailq, tmp) {
		fn(ctx, key);
	}

	if (flags & SPDK_KEYRING_FOR_EACH_ALL) {
		TAILQ_FOREACH_SAFE(key, &g_keyring.removed_keys, tailq, tmp) {
			fn(ctx, key);
		}
	}
	pthread_mutex_unlock(&g_keyring.mutex);
}

void
spdk_keyring_register_module(struct spdk_keyring_module *module)
{
	assert(keyring_find_module(module->name) == NULL);
	TAILQ_INSERT_TAIL(&g_keyring.modules, module, tailq);
}

void
keyring_dump_key_info(struct spdk_key *key, struct spdk_json_write_ctx *w)
{
	struct spdk_keyring_module *module = key->module;

	spdk_json_write_named_string(w, "name", key->name);
	spdk_json_write_named_string(w, "module", module->name);
	spdk_json_write_named_bool(w, "removed", key->removed);
	spdk_json_write_named_bool(w, "probed", key->probed);
	spdk_json_write_named_int32(w, "refcnt", key->refcnt);

	if (!key->removed && module->dump_info != NULL) {
		module->dump_info(key, w);
	}
}

int
spdk_keyring_init(void)
{
	struct spdk_keyring_module *module, *tmp;
	pthread_mutexattr_t attr;
	int rc;

	rc = pthread_mutexattr_init(&attr);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to initialize mutex attr\n");
		return -rc;
	}

	rc = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to set mutex attr\n");
		return -rc;
	}

	rc = pthread_mutex_init(&g_keyring.mutex, &attr);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to initialize mutex\n");
		return -rc;
	}

	TAILQ_FOREACH_SAFE(module, &g_keyring.modules, tailq, tmp) {
		if (module->init != NULL) {
			rc = module->init();
			if (rc != 0) {
				if (rc == -ENODEV) {
					SPDK_INFOLOG(keyring, "Skipping module %s\n", module->name);
					TAILQ_REMOVE(&g_keyring.modules, module, tailq);
					rc = 0;
					continue;
				}

				SPDK_ERRLOG("Failed to initialize module %s: %s\n",
					    module->name, spdk_strerror(-rc));
				break;
			}
		}

		SPDK_INFOLOG(keyring, "Initialized module %s\n", module->name);
	}

	if (rc != 0) {
		TAILQ_FOREACH(tmp, &g_keyring.modules, tailq) {
			if (tmp == module) {
				break;
			}
			if (tmp->cleanup != NULL) {
				tmp->cleanup();
			}
		}
	}

	return rc;
}

void
spdk_keyring_cleanup(void)
{
	struct spdk_keyring_module *module;
	struct spdk_key *key;

	while (!TAILQ_EMPTY(&g_keyring.keys)) {
		key = TAILQ_FIRST(&g_keyring.keys);
		if (!key->removed) {
			keyring_remove_key(key);
		}
	}

	while (!TAILQ_EMPTY(&g_keyring.removed_keys)) {
		key = TAILQ_FIRST(&g_keyring.removed_keys);
		SPDK_WARNLOG("Key '%s' still has %d references\n", key->name, key->refcnt);
		key->refcnt = 0;
		TAILQ_REMOVE(&g_keyring.removed_keys, key, tailq);
		keyring_free_key(key);
	}

	TAILQ_FOREACH(module, &g_keyring.modules, tailq) {
		if (module->cleanup != NULL) {
			module->cleanup();
		}
	}
}

SPDK_LOG_REGISTER_COMPONENT(keyring)
