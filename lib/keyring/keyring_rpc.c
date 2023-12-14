/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#include "keyring_internal.h"
#include "spdk/keyring.h"
#include "spdk/rpc.h"
#include "spdk/string.h"
#include "spdk/util.h"

struct rpc_keyring_add_key {
	char *name;
	char *module;
};

static const struct spdk_json_object_decoder rpc_keyring_add_key_decoders[] = {
	{"name", offsetof(struct rpc_keyring_add_key, name), spdk_json_decode_string},
	{"module", offsetof(struct rpc_keyring_add_key, module), spdk_json_decode_string},
};

static void
free_rpc_keyring_add_key(struct rpc_keyring_add_key *r)
{
	free(r->name);
	free(r->module);
}

static void
rpc_keyring_add_key(struct spdk_jsonrpc_request *request,
		    const struct spdk_json_val *params)
{
	struct rpc_keyring_add_key req = {};
	struct spdk_key_opts opts = {};
	int rc;

	if (spdk_json_decode_object_relaxed(params, rpc_keyring_add_key_decoders,
					    SPDK_COUNTOF(rpc_keyring_add_key_decoders),
					    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(EINVAL));
		return;
	}

	opts.size = SPDK_SIZEOF(&opts, opts);
	opts.name = req.name;
	opts.module = req.module;
	opts.opts = params;
	rc = spdk_keyring_add(&opts);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto out;
	}

	spdk_jsonrpc_send_bool_response(request, true);
out:
	free_rpc_keyring_add_key(&req);
}
SPDK_RPC_REGISTER("keyring_add_key", rpc_keyring_add_key, SPDK_RPC_RUNTIME)

struct rpc_keyring_remove_key {
	char *name;
};

static const struct spdk_json_object_decoder rpc_keyring_remove_key_decoders[] = {
	{"name", offsetof(struct rpc_keyring_remove_key, name), spdk_json_decode_string},
};

static void
free_rpc_keyring_remove_key(struct rpc_keyring_remove_key *r)
{
	free(r->name);
}

static void
rpc_keyring_remove_key(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_keyring_remove_key req = {};

	if (spdk_json_decode_object(params, rpc_keyring_remove_key_decoders,
				    SPDK_COUNTOF(rpc_keyring_remove_key_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(EINVAL));
		return;
	}

	spdk_keyring_remove(req.name);
	spdk_jsonrpc_send_bool_response(request, true);
	free_rpc_keyring_remove_key(&req);
}
SPDK_RPC_REGISTER("keyring_remove_key", rpc_keyring_remove_key, SPDK_RPC_RUNTIME)

static void
rpc_keyring_for_each_key_cb(void *ctx, struct spdk_key *key)
{
	struct spdk_json_write_ctx *w = ctx;

	spdk_json_write_object_begin(w);
	keyring_dump_key_info(key, w);
	spdk_json_write_object_end(w);
}

static void
rpc_keyring_get_keys(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_array_begin(w);
	spdk_keyring_for_each_key(w, rpc_keyring_for_each_key_cb);
	spdk_json_write_array_end(w);

	spdk_jsonrpc_end_result(request, w);

}
SPDK_RPC_REGISTER("keyring_get_keys", rpc_keyring_get_keys, SPDK_RPC_RUNTIME)
