/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#ifndef SPDK_KEYRING_H
#define SPDK_KEYRING_H

#include "spdk/stdinc.h"
#include "spdk/json.h"

struct spdk_key;

struct spdk_key_opts {
	/** Size of this structure */
	size_t size;
	/** Name of the key */
	const char *name;
	/** Name of the keyring module */
	const char *module;
	/** Module-specific options */
	const struct spdk_json_val *opts;
};

/**
 * Add a key to the keyring.
 *
 * \param opts Key options.
 *
 * \return 0 on success, negative errno otherwise.
 */
int spdk_keyring_add(const struct spdk_key_opts *opts);

/**
 * Remove a key from the keyring.
 *
 * \param name Name of the key to remove.
 */
void spdk_keyring_remove(const char *name);

/**
 * Get a reference to a key from the keyring.  The key must have been added to the keyring by
 * the appropriate keyring module.  The reference will be kept alive until its released via
 * `spdk_keyring_put()`.  If the key is removed from the keyring, the reference is kept alive, but
 * the key won't be usable anymore.
 *
 * \param name Name of a key.
 *
 * \return Reference to a key or NULL if the key doesn't exist.
 */
struct spdk_key *spdk_keyring_get(const char *name);

/**
 * Release a reference to a key obtained from `spdk_keyring_get()`.
 *
 * \param key Reference to a key.
 */
void spdk_keyring_put(struct spdk_key *key);

/**
 * Get the name of a key.
 *
 * \param key Reference to a key.
 *
 * \return Name of the key.
 */
const char *spdk_key_get_name(struct spdk_key *key);

/**
 * Retrieve keying material form a key reference.
 *
 * \param key Reference to a key.
 * \param buf Buffer to write the data to.
 * \param len Size of the `buf` buffer.
 *
 * \return The number of bytes written to `buf` or negative errno on error.
 */
int spdk_key_get_key(struct spdk_key *key, void *buf, int len);

/**
 * Initialize the keyring library.
 *
 * \return 0 on success, negative errno otherwise.
 */
int spdk_keyring_init(void);

/**
 * Free any resources acquired by the keyring library.  This function will free all of the keys.
 */
void spdk_keyring_cleanup(void);

/** Iterate over all keys including those that were removed, but still have active references */
#define SPDK_KEYRING_FOR_EACH_ALL 0x1

/**
 * Execute a function on each registered key.
 *
 * \param ctx Context to pass to the function.
 * \param fn Function to call.
 * \param flags Flags controlling the keys to iterate over.
 */
void spdk_keyring_for_each_key(void *ctx, void (*fn)(void *ctx, struct spdk_key *key),
			       uint32_t flags);

#endif /* SPDK_KEYRING_H */
