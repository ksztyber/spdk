/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Intel Corporation.  All rights reserved.
 */

#include "spdk/log.h"
#include "nvme_internal.h"

#define NVME_AUTH_DATA_SIZE 4096

#define AUTH_DEBUGLOG(q, fmt, ...)					\
	SPDK_DEBUGLOG(nvme_auth, "[nqn=%s:qid=%u] " fmt,		\
		      (q)->ctrlr->trid.subnqn, (q)->id, ## __VA_ARGS__)
#define AUTH_ERRLOG(q, fmt, ...) \
	SPDK_ERRLOG("[nqn=%s:qid=%u] " fmt, (q)->ctrlr->trid.subnqn, (q)->id, ## __VA_ARGS__)

static const char *
nvme_auth_get_state_name(int state)
{
	const char *sstr[] = {
		[NVME_QPAIR_AUTH_STATE_NEGOTIATE] = "negotiate",
		[NVME_QPAIR_AUTH_STATE_AWAIT_NEGOTIATE] = "await-negotiate",
		[NVME_QPAIR_AUTH_STATE_AWAIT_CHALLENGE] = "await-challenge",
		[NVME_QPAIR_AUTH_STATE_AWAIT_REPLY] = "await-reply",
		[NVME_QPAIR_AUTH_STATE_AWAIT_SUCCESS1] = "await-success1",
		[NVME_QPAIR_AUTH_STATE_AWAIT_FAILURE2] = "await-failure2",
		[NVME_QPAIR_AUTH_STATE_DONE] = "done",
	};

	if (state < 0 || state >= (int)SPDK_COUNTOF(sstr)) {
		return NULL;
	}

	return sstr[state];
}

static void
nvme_auth_set_state(struct spdk_nvme_qpair *qpair, enum nvme_qpair_auth_state state)
{
	AUTH_DEBUGLOG(qpair, "auth state: %s\n", nvme_auth_get_state_name(state));
	qpair->auth.state = state;
}

static void
nvme_auth_set_failure(struct spdk_nvme_qpair *qpair, int status, bool failure2)
{
	if (qpair->auth.status == 0) {
		qpair->auth.status = status;
	}

	nvme_auth_set_state(qpair, failure2 ?
			    NVME_QPAIR_AUTH_STATE_AWAIT_FAILURE2 :
			    NVME_QPAIR_AUTH_STATE_DONE);
}

int
nvme_fabric_qpair_authenticate_poll(struct spdk_nvme_qpair *qpair)
{
	struct nvme_auth *auth = &qpair->auth;
	struct nvme_completion_poll_status *status = qpair->poll_status;
	enum nvme_qpair_auth_state prev_state;
	int rc;

	do {
		prev_state = auth->state;

		switch (auth->state) {
		case NVME_QPAIR_AUTH_STATE_NEGOTIATE:
		case NVME_QPAIR_AUTH_STATE_AWAIT_NEGOTIATE:
		case NVME_QPAIR_AUTH_STATE_AWAIT_CHALLENGE:
		case NVME_QPAIR_AUTH_STATE_AWAIT_REPLY:
		case NVME_QPAIR_AUTH_STATE_AWAIT_SUCCESS1:
		case NVME_QPAIR_AUTH_STATE_AWAIT_FAILURE2:
			nvme_auth_set_failure(qpair, -ENOTSUP, false);
			break;
		case NVME_QPAIR_AUTH_STATE_DONE:
			rc = auth->status;
			if (qpair->poll_status != NULL && !status->timed_out) {
				qpair->poll_status = NULL;
				spdk_free(status->dma_data);
				free(status);
			}
			break;
		default:
			assert(0 && "invalid state");
			rc = -EINVAL;
			break;
		}
	} while (auth->state != prev_state);

	return rc;
}

int
nvme_fabric_qpair_authenticate_async(struct spdk_nvme_qpair *qpair)
{
	struct spdk_nvme_ctrlr *ctrlr = qpair->ctrlr;
	struct nvme_completion_poll_status *status;
	struct nvme_auth *auth = &qpair->auth;

	if (ctrlr->opts.chap_key == NULL) {
		AUTH_ERRLOG(qpair, "missing DH-HMAC-CHAP key\n");
		return -ENOKEY;
	}

	if (qpair->auth.flags & NVME_QPAIR_AUTH_FLAG_ASCR) {
		AUTH_ERRLOG(qpair, "secure channel concatentation is not supported\n");
		return -EINVAL;
	}

	status = calloc(1, sizeof(*qpair->poll_status));
	if (!status) {
		AUTH_ERRLOG(qpair, "failed to allocate poll status\n");
		return -ENOMEM;
	}

	status->dma_data = spdk_zmalloc(NVME_AUTH_DATA_SIZE, 0, NULL, SPDK_ENV_LCORE_ID_ANY,
					SPDK_MALLOC_DMA);
	if (!status->dma_data) {
		AUTH_ERRLOG(qpair, "failed to allocate poll status\n");
		free(status);
		return -ENOMEM;
	}

	assert(qpair->poll_status == NULL);
	qpair->poll_status = status;

	nvme_robust_mutex_lock(&ctrlr->ctrlr_lock);
	auth->tid = ctrlr->auth_tid++;
	nvme_robust_mutex_unlock(&ctrlr->ctrlr_lock);

	nvme_auth_set_state(qpair, NVME_QPAIR_AUTH_STATE_NEGOTIATE);

	return 0;
}
SPDK_LOG_REGISTER_COMPONENT(nvme_auth)
