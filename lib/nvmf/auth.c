/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Intel Corporation.  All rights reserved.
 */

#include "spdk/log.h"
#include "spdk/stdinc.h"

#include "nvmf_internal.h"

#define AUTH_ERRLOG(q, fmt, ...) \
	SPDK_ERRLOG("[%s:%s:%u] " fmt, (q)->ctrlr->subsys->subnqn, (q)->ctrlr->hostnqn, \
		    (q)->qid, ## __VA_ARGS__)
#define AUTH_DEBUGLOG(q, fmt, ...) \
	SPDK_DEBUGLOG(nvmf_auth, "[%s:%s:%u] " fmt, \
		      (q)->ctrlr->subsys->subnqn, (q)->ctrlr->hostnqn, (q)->qid, ## __VA_ARGS__)

enum nvmf_qpair_auth_state {
	NVMF_QPAIR_AUTH_NEGOTIATE,
};

struct spdk_nvmf_qpair_auth {
	enum nvmf_qpair_auth_state state;
};

static void
nvmf_auth_request_complete(struct spdk_nvmf_request *req, int sct, int sc, int dnr)
{
	struct spdk_nvme_cpl *response = &req->rsp->nvme_cpl;

	response->status.sct = sct;
	response->status.sc = sc;
	response->status.dnr = dnr;

	spdk_nvmf_request_complete(req);
}

 __attribute__((unused)) static const char *
nvmf_auth_get_state_name(enum nvmf_qpair_auth_state state)
{
	static const char *state_names[] = {
		[NVMF_QPAIR_AUTH_NEGOTIATE] = "negotiate",
	};

	return state_names[state];
}

static void
nvmf_auth_set_state(struct spdk_nvmf_qpair *qpair, enum nvmf_qpair_auth_state state)
{
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;

	AUTH_DEBUGLOG(qpair, "auth state: %s\n", nvmf_auth_get_state_name(state));
	auth->state = state;
}

static int
nvmf_auth_check_command(struct spdk_nvmf_request *req, uint8_t secp,
			uint8_t spsp0, uint8_t spsp1, uint32_t len)
{
	struct spdk_nvmf_qpair *qpair = req->qpair;

	if (secp != SPDK_NVMF_AUTH_SECP_NVME) {
		AUTH_ERRLOG(qpair, "invalid secp=%u\n", secp);
		return -EINVAL;
	}
	if (spsp0 != 1 || spsp1 != 1) {
		AUTH_ERRLOG(qpair, "invalid spsp0=%u, spsp1=%u\n", spsp0, spsp1);
		return -EINVAL;
	}
	if (len != req->length) {
		AUTH_ERRLOG(qpair, "invalid length: %"PRIu32" != %"PRIu32"\n", len, req->length);
		return -EINVAL;
	}

	return 0;
}

static void
nvmf_auth_send_exec(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_fabric_auth_send_cmd *cmd = &req->cmd->auth_send_cmd;
	int rc;

	rc = nvmf_auth_check_command(req, cmd->secp, cmd->spsp0, cmd->spsp1, cmd->tl);
	if (rc != 0) {
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INVALID_FIELD, 1);
		return;
	}

	nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
				   SPDK_NVME_SC_INVALID_OPCODE, 1);
}

static void
nvmf_auth_recv_exec(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_fabric_auth_recv_cmd *cmd = &req->cmd->auth_recv_cmd;
	int rc;

	rc = nvmf_auth_check_command(req, cmd->secp, cmd->spsp0, cmd->spsp1, cmd->al);
	if (rc != 0) {
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INVALID_FIELD, 1);
		return;
	}

	nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
				   SPDK_NVME_SC_INVALID_OPCODE, 1);
}

void
nvmf_auth_request_exec(struct spdk_nvmf_request *req)
{
	union nvmf_h2c_msg *cmd = req->cmd;

	assert(cmd->nvmf_cmd.opcode == SPDK_NVME_OPC_FABRIC);
	switch (cmd->nvmf_cmd.fctype) {
	case SPDK_NVMF_FABRIC_COMMAND_AUTHENTICATION_SEND:
		nvmf_auth_send_exec(req);
		break;
	case SPDK_NVMF_FABRIC_COMMAND_AUTHENTICATION_RECV:
		nvmf_auth_recv_exec(req);
		break;
	default:
		assert(0 && "invalid fctype");
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INTERNAL_DEVICE_ERROR, 0);
		break;
	}
}

int
nvmf_qpair_auth_init(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_qpair_auth *auth;

	assert(qpair->auth == NULL);
	auth = calloc(1, sizeof(*qpair->auth));
	if (auth == NULL) {
		return -ENOMEM;
	}

	qpair->auth = auth;
	nvmf_auth_set_state(qpair, NVMF_QPAIR_AUTH_NEGOTIATE);

	return 0;
}

void
nvmf_qpair_auth_destroy(struct spdk_nvmf_qpair *qpair)
{
	free(qpair->auth);
	qpair->auth = NULL;
}
SPDK_LOG_REGISTER_COMPONENT(nvmf_auth)
