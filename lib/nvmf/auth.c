/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Intel Corporation.  All rights reserved.
 */

#include "spdk/nvme.h"
#include "spdk/log.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"

#include "nvmf_internal.h"

#define NVMF_AUTH_DEFAULT_KATO_US (120ull * 1000 * 1000)

#define AUTH_ERRLOG(q, fmt, ...) \
	SPDK_ERRLOG("[%s:%s:%u] " fmt, (q)->ctrlr->subsys->subnqn, (q)->ctrlr->hostnqn, \
		    (q)->qid, ## __VA_ARGS__)
#define AUTH_DEBUGLOG(q, fmt, ...) \
	SPDK_DEBUGLOG(nvmf_auth, "[%s:%s:%u] " fmt, \
		      (q)->ctrlr->subsys->subnqn, (q)->ctrlr->hostnqn, (q)->qid, ## __VA_ARGS__)

enum nvmf_qpair_auth_state {
	NVMF_QPAIR_AUTH_NEGOTIATE,
	NVMF_QPAIR_AUTH_FAILURE1,
	NVMF_QPAIR_AUTH_ERROR,
};

struct spdk_nvmf_qpair_auth {
	enum nvmf_qpair_auth_state	state;
	struct spdk_poller		*poller;
	int				fail_reason;
	uint16_t			tid;
	int				digest;
};

struct nvmf_auth_common_header {
	uint8_t		auth_type;
	uint8_t		auth_id;
	uint8_t		reserved0[2];
	uint16_t	t_id;
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

static const char *
nvmf_auth_get_state_name(enum nvmf_qpair_auth_state state)
{
	static const char *state_names[] = {
		[NVMF_QPAIR_AUTH_NEGOTIATE] = "negotiate",
		[NVMF_QPAIR_AUTH_FAILURE1] = "failure1",
		[NVMF_QPAIR_AUTH_ERROR] = "error",
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

static void
nvmf_auth_set_failure1(struct spdk_nvmf_qpair *qpair, int reason)
{
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;

	nvmf_auth_set_state(qpair, NVMF_QPAIR_AUTH_FAILURE1);
	auth->fail_reason = reason;
}

static int
nvmf_auth_timeout_poller(void *ctx)
{
	struct spdk_nvmf_qpair *qpair = ctx;
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;

	AUTH_ERRLOG(qpair, "authentication timed out\n");

	spdk_poller_unregister(&auth->poller);
	nvmf_auth_set_state(qpair, NVMF_QPAIR_AUTH_ERROR);
	spdk_nvmf_qpair_disconnect(qpair, NULL, NULL);

	return SPDK_POLLER_BUSY;
}

static int
nvmf_auth_rearm_poller(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_ctrlr *ctrlr = qpair->ctrlr;
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;
	uint64_t timeout;

	timeout = ctrlr->feat.keep_alive_timer.bits.kato > 0 ?
		  ctrlr->feat.keep_alive_timer.bits.kato * 1000 :
		  NVMF_AUTH_DEFAULT_KATO_US;

	spdk_poller_unregister(&auth->poller);
	auth->poller = SPDK_POLLER_REGISTER(nvmf_auth_timeout_poller, qpair, timeout);
	if (auth->poller == NULL) {
		return -ENOMEM;
	}

	return 0;
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

static void *
nvmf_auth_get_message(struct spdk_nvmf_request *req, size_t size)
{
	if (req->length > 0 && req->iovcnt == 1 && req->iov[0].iov_len >= size) {
		return req->iov[0].iov_base;
	}

	return NULL;
}

static int
nvmf_auth_negotiate_exec(struct spdk_nvmf_request *req, struct spdk_nvmf_auth_negotiate *msg)
{
	struct spdk_nvmf_qpair *qpair = req->qpair;
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;
	struct spdk_nvmf_auth_descriptor *desc = NULL;
	enum spdk_nvmf_auth_hash digests[] = {
		SPDK_NVMF_AUTH_HASH_SHA512,
		SPDK_NVMF_AUTH_HASH_SHA384,
		SPDK_NVMF_AUTH_HASH_SHA256
	};
	enum spdk_nvmf_auth_dhgroup dhgroups[] = {
		SPDK_NVMF_AUTH_DHGROUP_NULL,
	};
	int digest = -1, dhgroup = -1;
	size_t i, j;

	if (auth->state != NVMF_QPAIR_AUTH_NEGOTIATE) {
		AUTH_ERRLOG(qpair, "invalid state: %s\n", nvmf_auth_get_state_name(auth->state));
		return SPDK_NVMF_AUTH_INCORRECT_PROTOCOL_MESSAGE;
	}

	auth->tid = msg->t_id;
	if (req->length < sizeof(*msg) || req->length != sizeof(*msg) + msg->napd * sizeof(*desc)) {
		AUTH_ERRLOG(qpair, "invalid message length: %"PRIu32"\n", req->length);
		return SPDK_NVMF_AUTH_INCORRECT_PAYLOAD;
	}

	if (msg->sc_c != SPDK_NVMF_AUTH_SCC_DISABLED) {
		AUTH_ERRLOG(qpair, "scc mismatch\n");
		return SPDK_NVMF_AUTH_SCC_MISMATCH;
	}

	for (i = 0; i < msg->napd; ++i) {
		if (msg->descriptors[i].auth_id == SPDK_NVMF_AUTH_TYPE_DH_HMAC_CHAP) {
			desc = &msg->descriptors[i];
			break;
		}
	}
	if (desc == NULL) {
		AUTH_ERRLOG(qpair, "no usable protocol found\n");
		return SPDK_NVMF_AUTH_PROTOCOL_UNUSABLE;
	}
	if (desc->halen > SPDK_COUNTOF(desc->hash_id_list) ||
	    desc->dhlen > SPDK_COUNTOF(desc->dhg_id_list)) {
		AUTH_ERRLOG(qpair, "invalid halen=%u, dhlen=%u\n", desc->halen, desc->dhlen);
		return SPDK_NVMF_AUTH_INCORRECT_PAYLOAD;
	}

	for (i = 0; i < SPDK_COUNTOF(digests); ++i) {
		for (j = 0; j < desc->halen; ++j) {
			if (digests[i] == desc->hash_id_list[j]) {
				AUTH_DEBUGLOG(qpair, "selected digest: %s\n",
					      spdk_nvme_auth_get_digest_name(digests[i]));
				digest = digests[i];
				break;
			}
		}
		if (digest > 0) {
			break;
		}
	}
	if (digest < 0) {
		AUTH_ERRLOG(qpair, "no usable digests found\n");
		return SPDK_NVMF_AUTH_HASH_UNUSABLE;
	}

	for (i = 0; i < SPDK_COUNTOF(dhgroups); ++i) {
		for (j = 0; j < desc->dhlen; ++j) {
			if (dhgroups[i] == desc->dhg_id_list[j]) {
				AUTH_DEBUGLOG(qpair, "selected dhgroup: %s\n",
					      spdk_nvme_auth_get_dhgroup_name(dhgroups[i]));
				dhgroup = dhgroups[i];
				break;
			}
		}
		if (dhgroup > 0) {
			break;
		}
	}
	if (dhgroup < 0) {
		AUTH_ERRLOG(qpair, "no usable dhgroups found\n");
		return SPDK_NVMF_AUTH_DHGROUP_UNUSABLE;
	}

	auth->digest = digest;

	return 0;
}

static void
nvmf_auth_send_exec(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_qpair *qpair = req->qpair;
	struct spdk_nvmf_fabric_auth_send_cmd *cmd = &req->cmd->auth_send_cmd;
	struct nvmf_auth_common_header *header;
	int rc;

	rc = nvmf_auth_check_command(req, cmd->secp, cmd->spsp0, cmd->spsp1, cmd->tl);
	if (rc != 0) {
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INVALID_FIELD, 1);
		return;
	}

	if (nvmf_auth_rearm_poller(qpair)) {
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INTERNAL_DEVICE_ERROR, 0);
		spdk_nvmf_qpair_disconnect(qpair, NULL, NULL);
		return;
	}

	header = nvmf_auth_get_message(req, sizeof(*header));
	if (header == NULL) {
		rc = SPDK_NVMF_AUTH_INCORRECT_PAYLOAD;
		goto out;
	}

	switch (header->auth_type) {
	case SPDK_NVMF_AUTH_TYPE_COMMON_MESSAGE:
		switch (header->auth_id) {
		case SPDK_NVMF_AUTH_ID_NEGOTIATE:
			rc = nvmf_auth_negotiate_exec(req, (void *)header);
			break;
		default:
			AUTH_ERRLOG(qpair, "unexpected auth_id=%u\n", header->auth_id);
			rc = SPDK_NVMF_AUTH_INCORRECT_PROTOCOL_MESSAGE;
			break;
		}
		break;
	case SPDK_NVMF_AUTH_TYPE_DH_HMAC_CHAP:
	default:
		rc = SPDK_NVMF_AUTH_INCORRECT_PROTOCOL_MESSAGE;
		break;
	}
out:
	if (rc != 0) {
		nvmf_auth_set_failure1(qpair, rc);
	}
	nvmf_auth_request_complete(req, 0, 0, 0);
}

static void
nvmf_auth_recv_failure1(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_qpair *qpair = req->qpair;
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;
	struct spdk_nvmf_auth_failure *failure;

	failure = nvmf_auth_get_message(req, sizeof(*failure));
	if (failure == NULL) {
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INVALID_FIELD, 1);
		spdk_nvmf_qpair_disconnect(qpair, NULL, NULL);
		return;
	}

	memset(failure, 0, sizeof(*failure));
	failure->auth_type = SPDK_NVMF_AUTH_TYPE_COMMON_MESSAGE;
	failure->auth_id = SPDK_NVMF_AUTH_ID_FAILURE1;
	failure->t_id = auth->tid;
	failure->rc = SPDK_NVMF_AUTH_FAILURE;
	failure->rce = auth->fail_reason;

	nvmf_auth_request_complete(req, 0, 0, 0);
	spdk_nvmf_qpair_disconnect(qpair, NULL, NULL);
}

static void
nvmf_auth_recv_exec(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_qpair *qpair = req->qpair;
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;
	struct spdk_nvmf_fabric_auth_recv_cmd *cmd = &req->cmd->auth_recv_cmd;
	int rc;

	rc = nvmf_auth_check_command(req, cmd->secp, cmd->spsp0, cmd->spsp1, cmd->al);
	if (rc != 0) {
		nvmf_auth_request_complete(req, SPDK_NVME_SCT_GENERIC,
					   SPDK_NVME_SC_INVALID_FIELD, 1);
		return;
	}

	switch (auth->state) {
	case NVMF_QPAIR_AUTH_FAILURE1:
		nvmf_auth_recv_failure1(req);
		break;
	default:
		nvmf_auth_set_failure1(qpair, SPDK_NVMF_AUTH_INCORRECT_PROTOCOL_MESSAGE);
		nvmf_auth_recv_failure1(req);
		break;
	}
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
	int rc;

	assert(qpair->auth == NULL);
	auth = calloc(1, sizeof(*qpair->auth));
	if (auth == NULL) {
		return -ENOMEM;
	}

	auth->digest = -1;
	qpair->auth = auth;
	nvmf_auth_set_state(qpair, NVMF_QPAIR_AUTH_NEGOTIATE);

	rc = nvmf_auth_rearm_poller(qpair);
	if (rc != 0) {
		AUTH_ERRLOG(qpair, "failed to arm timeout poller: %s\n", spdk_strerror(-rc));
		nvmf_qpair_auth_destroy(qpair);
		return rc;
	}

	return 0;
}

void
nvmf_qpair_auth_destroy(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_qpair_auth *auth = qpair->auth;

	if (auth != NULL) {
		spdk_poller_unregister(&auth->poller);
		free(qpair->auth);
		qpair->auth = NULL;
	}
}
SPDK_LOG_REGISTER_COMPONENT(nvmf_auth)
