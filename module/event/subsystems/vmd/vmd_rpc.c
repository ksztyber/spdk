/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 */

#include "spdk/vmd.h"

#include "spdk/env.h"
#include "spdk/rpc.h"
#include "spdk/string.h"
#include "spdk/util.h"

#include "spdk/log.h"
#include "event_vmd.h"

static void
rpc_vmd_enable(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	vmd_subsystem_enable();

	spdk_jsonrpc_send_bool_response(request, true);
}
SPDK_RPC_REGISTER("vmd_enable", rpc_vmd_enable, SPDK_RPC_STARTUP)
SPDK_RPC_REGISTER_ALIAS_DEPRECATED(vmd_enable, enable_vmd)

struct vmd_remove_device_ctx {
	struct spdk_pci_addr	addr;
	int			status;
};

static void
remove_device_foreach_cb(void *_ctx, struct spdk_pci_device *dev)
{
	struct vmd_remove_device_ctx *ctx = _ctx;
	struct spdk_pci_addr addr = spdk_pci_device_get_addr(dev);

	if (spdk_pci_addr_compare(&addr, &ctx->addr) != 0) {
		return;
	}

	ctx->status = spdk_vmd_remove_device(dev);
}

struct rpc_vmd_remove_device {
	char *addr;
};

static const struct spdk_json_object_decoder rpc_vmd_remove_device_decoders[] = {
	{"addr", offsetof(struct rpc_vmd_remove_device, addr), spdk_json_decode_string},
};

static void
rpc_vmd_remove_device(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct vmd_remove_device_ctx ctx = { .status = -ENODEV };
	struct rpc_vmd_remove_device req = {};
	int rc;

	if (!vmd_subsystem_is_enabled()) {
		spdk_jsonrpc_send_error_response(request, -ENODEV, "VMD subsystem is disabled");
		return;
	}

	rc = spdk_json_decode_object(params, rpc_vmd_remove_device_decoders,
				     SPDK_COUNTOF(rpc_vmd_remove_device_decoders),
				     &req);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		return;
	}

	rc = spdk_pci_addr_parse(&ctx.addr, req.addr);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto out;
	}

	spdk_pci_for_each_device(&ctx, remove_device_foreach_cb);
	if (ctx.status != 0) {
		spdk_jsonrpc_send_error_response(request, ctx.status, spdk_strerror(ctx.status));
		goto out;
	}

	spdk_jsonrpc_send_bool_response(request, true);
out:
	free(req.addr);
}
SPDK_RPC_REGISTER("vmd_remove_device", rpc_vmd_remove_device, SPDK_RPC_RUNTIME)
