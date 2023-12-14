/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#ifndef SPDK_KEYRING_MODULE_H
#define SPDK_KEYRING_MODULE_H

#include "spdk/stdinc.h"
#include "spdk/keyring.h"
#include "spdk/queue.h"

struct spdk_keyring_module {
	/** Name of the module */
	const char *name;

	/** Initializes a module, called during keyring's initialization */
	int (*init)(void);
	/** Clean up resources allocated by a module.  Called during keyring's cleanup  */
	void (*cleanup)(void);
	/** Write module configuration to JSON */
	void (*write_config)(struct spdk_json_write_ctx *w);
	/** Add a key to the keyring */
	int (*add_key)(struct spdk_key *key, const struct spdk_json_val *opts);
	/** Remove a key from the keyring */
	void (*remove_key)(struct spdk_key *key);
	/** Get keying material from a key */
	int (*get_key)(struct spdk_key *key, void *buf, int len);
	/** Get the size of the context associated with a key */
	size_t (*get_ctx_size)(void);
	/** Dump information about a key to JSON */
	void (*dump_info)(struct spdk_key *key, struct spdk_json_write_ctx *w);

	TAILQ_ENTRY(spdk_keyring_module) tailq;
};

/**
 * Register a keyring module.
 *
 * \param module Keyring module to register.
 */
void spdk_keyring_register_module(struct spdk_keyring_module *module);

#define SPDK_KEYRING_REGISTER_MODULE(name, module) \
static void __attribute__((constructor)) _spdk_keyring_register_##name(void) \
{ \
	spdk_keyring_register_module(module); \
}

/**
 * Get pointer to the module context associated with a key.
 *
 * \param key Key.
 *
 * \return Key context.
 */
void *spdk_key_get_ctx(struct spdk_key *key);

/**
 * Get keyring module owning the key.
 *
 * \param key Key.
 *
 * \return Key owner.
 */
struct spdk_keyring_module *spdk_key_get_module(struct spdk_key *key);

#endif /* SPDK_KEYRING_H */
