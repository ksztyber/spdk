/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Intel Corporation. All rights reserved.
 */
#include "spdk/stdinc.h"

#include "spdk_internal/cunit.h"
#include "spdk_internal/mock.h"

#include "common/lib/ut_multithread.c"
#include "nvmf/auth.c"

DEFINE_STUB(spdk_nvme_auth_get_digest_name, const char *, (int d), NULL);
DEFINE_STUB(spdk_nvme_auth_get_dhgroup_name, const char *, (int d), NULL);

int
spdk_nvmf_qpair_disconnect(struct spdk_nvmf_qpair *qpair,
			   nvmf_qpair_disconnect_cb cb_fn, void *cb_arg)
{
	qpair->state = SPDK_NVMF_QPAIR_ERROR;
	return 0;
}

static bool g_req_completed;

int
spdk_nvmf_request_complete(struct spdk_nvmf_request *req)
{
	g_req_completed = true;
	return 0;
}

static void
ut_clear_resp(struct spdk_nvmf_request *req)
{
	memset(&req->rsp->nvme_cpl, 0, sizeof(req->rsp->nvme_cpl));
}

static void
test_auth_negotiate(void)
{
	union nvmf_c2h_msg rsp = {};
	struct spdk_nvmf_subsystem subsys = {};
	struct spdk_nvmf_ctrlr ctrlr = { .subsys = &subsys };
	struct spdk_nvmf_qpair qpair = { .ctrlr = &ctrlr };
	struct spdk_nvmf_request req = { .qpair = &qpair, .rsp = &rsp };
	struct spdk_nvmf_fabric_auth_send_cmd cmd = {};
	struct spdk_nvmf_qpair_auth *auth;
	struct spdk_nvmf_auth_negotiate *msg;
	struct spdk_nvmf_auth_descriptor *desc;
	uint8_t msgbuf[4096];
	int rc;

	msg = (void *)msgbuf;
	rc = nvmf_qpair_auth_init(&qpair);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	auth = qpair.auth;

	/* Successful negotiation */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	req.iovcnt = 1;
	req.iov[0].iov_base = msgbuf;
	req.iov[0].iov_len = sizeof(msgbuf);
	req.cmd = (void *)&cmd;
	cmd.secp = SPDK_NVMF_AUTH_SECP_NVME;
	cmd.spsp0 = 1;
	cmd.spsp1 = 1;
	cmd.tl = req.length = sizeof(*msg) + sizeof(*desc);

	msg->auth_type = SPDK_NVMF_AUTH_TYPE_COMMON_MESSAGE;
	msg->auth_id = SPDK_NVMF_AUTH_ID_NEGOTIATE;
	msg->sc_c = SPDK_NVMF_AUTH_SCC_DISABLED;
	msg->napd = 1;
	desc = &msg->descriptors[0];
	desc->auth_id = SPDK_NVMF_AUTH_TYPE_DH_HMAC_CHAP;
	desc->halen = 3;
	desc->hash_id_list[0] = SPDK_NVMF_AUTH_HASH_SHA256;
	desc->hash_id_list[1] = SPDK_NVMF_AUTH_HASH_SHA384;
	desc->hash_id_list[2] = SPDK_NVMF_AUTH_HASH_SHA512;
	desc->dhlen = 6;
	desc->dhg_id_list[0] = SPDK_NVMF_AUTH_DHGROUP_NULL;
	desc->dhg_id_list[1] = SPDK_NVMF_AUTH_DHGROUP_2048;
	desc->dhg_id_list[2] = SPDK_NVMF_AUTH_DHGROUP_3072;
	desc->dhg_id_list[3] = SPDK_NVMF_AUTH_DHGROUP_4096;
	desc->dhg_id_list[4] = SPDK_NVMF_AUTH_DHGROUP_6144;
	desc->dhg_id_list[5] = SPDK_NVMF_AUTH_DHGROUP_8192;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, SPDK_NVMF_AUTH_HASH_SHA512);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_NEGOTIATE);

	/* Invalid auth state */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_ERROR;
	auth->digest = -1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PROTOCOL_MESSAGE);

	/* scc mismatch */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	msg->sc_c = SPDK_NVMF_AUTH_SCC_TLS;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_SCC_MISMATCH);
	msg->sc_c = SPDK_NVMF_AUTH_SCC_DISABLED;

	/* Missing DH-HMAC-CHAP protocol (napd=0) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg);
	msg->napd = 0;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_PROTOCOL_UNUSABLE);
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg) + sizeof(*desc);
	msg->napd = 1;

	/* Missing DH-HMAC-CHAP protocol */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->auth_id = SPDK_NVMF_AUTH_TYPE_DH_HMAC_CHAP + 1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_PROTOCOL_UNUSABLE);
	desc->auth_id = SPDK_NVMF_AUTH_TYPE_DH_HMAC_CHAP;

	/* No valid digests (halen=0) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->halen = 0;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_HASH_UNUSABLE);

	/* No valid digests */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->hash_id_list[0] = SPDK_NVMF_AUTH_HASH_SHA512 + 1;
	desc->hash_id_list[1] = SPDK_NVMF_AUTH_HASH_SHA512 + 2;
	desc->hash_id_list[2] = SPDK_NVMF_AUTH_HASH_SHA512 + 3;
	desc->halen = 3;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_HASH_UNUSABLE);
	desc->hash_id_list[0] = SPDK_NVMF_AUTH_HASH_SHA256;
	desc->hash_id_list[1] = SPDK_NVMF_AUTH_HASH_SHA384;
	desc->hash_id_list[2] = SPDK_NVMF_AUTH_HASH_SHA512;

	/* No valid dhgroups (dhlen=0) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->dhlen = 0;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_DHGROUP_UNUSABLE);

	/* No valid dhgroups */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->dhlen = 2;
	desc->dhg_id_list[0] = SPDK_NVMF_AUTH_DHGROUP_8192 + 1;
	desc->dhg_id_list[1] = SPDK_NVMF_AUTH_DHGROUP_8192 + 2;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_DHGROUP_UNUSABLE);
	desc->dhg_id_list[0] = SPDK_NVMF_AUTH_DHGROUP_NULL;
	desc->dhg_id_list[1] = SPDK_NVMF_AUTH_DHGROUP_2048;
	desc->dhlen = 6;

	/* Bad halen value */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->halen = 255;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);
	desc->halen = 3;

	/* Bad dhlen value */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	desc->dhlen = 255;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);
	desc->dhlen = 6;

	/* Invalid request length (too small) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg) - 1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);

	/* Invalid request length (too small) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg);

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);

	/* Invalid request length (too small) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg) + sizeof(*desc) - 1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);

	/* Invalid request length (too large) */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg) + sizeof(*desc) + 1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->digest, -1);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);
	req.length = cmd.tl = req.iov[0].iov_len = sizeof(*msg) + sizeof(*desc);

	nvmf_qpair_auth_destroy(&qpair);
}

static void
test_auth_send_recv_error(void)
{
	union nvmf_c2h_msg rsp = {};
	struct spdk_nvmf_subsystem subsys = {};
	struct spdk_nvmf_ctrlr ctrlr = { .subsys = &subsys };
	struct spdk_nvmf_qpair qpair = { .ctrlr = &ctrlr };
	struct spdk_nvmf_request req = { .qpair = &qpair, .rsp = &rsp };
	struct spdk_nvme_cpl *cpl = &rsp.nvme_cpl;
	struct spdk_nvmf_fabric_auth_send_cmd send_cmd = {};
	struct spdk_nvmf_fabric_auth_recv_cmd recv_cmd = {};
	struct spdk_nvmf_qpair_auth *auth;
	int rc;

	rc = nvmf_qpair_auth_init(&qpair);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	auth = qpair.auth;

	req.length = 255;
	send_cmd.secp = recv_cmd.secp = SPDK_NVMF_AUTH_SECP_NVME;
	send_cmd.spsp0 = recv_cmd.spsp0 = 1;
	send_cmd.spsp1 = recv_cmd.spsp1 = 1;
	send_cmd.tl = recv_cmd.al = req.length;

	/* Bad secp (send) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&send_cmd;
	ut_clear_resp(&req);
	send_cmd.secp = SPDK_NVMF_AUTH_SECP_NVME + 1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	send_cmd.secp = SPDK_NVMF_AUTH_SECP_NVME;

	/* Bad secp (recv) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&recv_cmd;
	ut_clear_resp(&req);
	recv_cmd.secp = SPDK_NVMF_AUTH_SECP_NVME + 1;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	recv_cmd.secp = SPDK_NVMF_AUTH_SECP_NVME;

	/* Bad spsp0 (send) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&send_cmd;
	ut_clear_resp(&req);
	send_cmd.spsp0 = 2;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	send_cmd.spsp0 = 1;

	/* Bad spsp0 (recv) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&recv_cmd;
	ut_clear_resp(&req);
	recv_cmd.spsp0 = 2;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	recv_cmd.spsp0 = 1;

	/* Bad spsp1 (send) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&send_cmd;
	ut_clear_resp(&req);
	send_cmd.spsp1 = 2;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	send_cmd.spsp1 = 1;

	/* Bad spsp1 (recv) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&recv_cmd;
	ut_clear_resp(&req);
	recv_cmd.spsp1 = 2;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	recv_cmd.spsp1 = 1;

	/* Bad length (send) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&send_cmd;
	ut_clear_resp(&req);
	send_cmd.tl = req.length + 1;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	send_cmd.tl = req.length;

	/* Bad length (recv) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&recv_cmd;
	ut_clear_resp(&req);
	recv_cmd.al = req.length - 1;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	recv_cmd.al = req.length;

	/* Bad length (smaller than common header) */
	g_req_completed = false;
	req.cmd = (union nvmf_h2c_msg *)&send_cmd;
	ut_clear_resp(&req);
	send_cmd.tl = req.length = sizeof(struct nvmf_auth_common_header) - 1;

	nvmf_auth_send_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(auth->fail_reason, SPDK_NVMF_AUTH_INCORRECT_PAYLOAD);
	send_cmd.tl = req.length = 255;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	auth->fail_reason = 0;

	nvmf_qpair_auth_destroy(&qpair);
}

static void
test_auth_recv_failure1(void)
{
	union nvmf_c2h_msg rsp = {};
	struct spdk_nvmf_subsystem subsys = {};
	struct spdk_nvmf_ctrlr ctrlr = { .subsys = &subsys };
	struct spdk_nvmf_qpair qpair = { .ctrlr = &ctrlr };
	struct spdk_nvmf_request req = { .qpair = &qpair, .rsp = &rsp };
	struct spdk_nvmf_fabric_auth_recv_cmd cmd = {};
	struct spdk_nvme_cpl *cpl = &rsp.nvme_cpl;
	struct spdk_nvmf_qpair_auth *auth;
	struct spdk_nvmf_auth_failure *msg;
	uint8_t msgbuf[sizeof(*msg)];
	int rc;

	msg = (void *)msgbuf;
	rc = nvmf_qpair_auth_init(&qpair);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	auth = qpair.auth;
	qpair.state = SPDK_NVMF_QPAIR_AUTHENTICATING;
	req.length = sizeof(msgbuf);
	req.iovcnt = 1;
	req.iov[0].iov_base = msgbuf;
	req.iov[0].iov_len = sizeof(msgbuf);
	req.cmd = (union nvmf_h2c_msg *)&cmd;
	cmd.secp = SPDK_NVMF_AUTH_SECP_NVME;
	cmd.spsp0 = 1;
	cmd.spsp1 = 1;
	cmd.al = req.length = sizeof(*msg);

	/* Check failure1 message fields */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_FAILURE1;
	auth->fail_reason = SPDK_NVMF_AUTH_FAILED;
	auth->tid = 8;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, 0);
	CU_ASSERT_EQUAL(cpl->status.sc, 0);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(qpair.state, SPDK_NVMF_QPAIR_ERROR);
	CU_ASSERT_EQUAL(msg->auth_type, SPDK_NVMF_AUTH_TYPE_COMMON_MESSAGE);
	CU_ASSERT_EQUAL(msg->auth_id, SPDK_NVMF_AUTH_ID_FAILURE1);
	CU_ASSERT_EQUAL(msg->t_id, 8);
	CU_ASSERT_EQUAL(msg->rc, SPDK_NVMF_AUTH_FAILURE);
	CU_ASSERT_EQUAL(msg->rce, SPDK_NVMF_AUTH_FAILED);
	qpair.state = SPDK_NVMF_QPAIR_AUTHENTICATING;

	/* Do a receive while expecting an auth send command */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_NEGOTIATE;
	auth->fail_reason = 0;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, 0);
	CU_ASSERT_EQUAL(cpl->status.sc, 0);
	CU_ASSERT_EQUAL(auth->state, NVMF_QPAIR_AUTH_FAILURE1);
	CU_ASSERT_EQUAL(qpair.state, SPDK_NVMF_QPAIR_ERROR);
	CU_ASSERT_EQUAL(msg->auth_type, SPDK_NVMF_AUTH_TYPE_COMMON_MESSAGE);
	CU_ASSERT_EQUAL(msg->auth_id, SPDK_NVMF_AUTH_ID_FAILURE1);
	CU_ASSERT_EQUAL(msg->t_id, 8);
	CU_ASSERT_EQUAL(msg->rc, SPDK_NVMF_AUTH_FAILURE);
	CU_ASSERT_EQUAL(msg->rce, SPDK_NVMF_AUTH_INCORRECT_PROTOCOL_MESSAGE);
	qpair.state = SPDK_NVMF_QPAIR_AUTHENTICATING;

	/* Do a receive but specify a buffer that's too small */
	g_req_completed = false;
	auth->state = NVMF_QPAIR_AUTH_FAILURE1;
	auth->fail_reason = SPDK_NVMF_AUTH_FAILED;
	req.iov[0].iov_len = cmd.al = req.length = sizeof(*msg) - 1;

	nvmf_auth_recv_exec(&req);
	CU_ASSERT(g_req_completed);
	CU_ASSERT_EQUAL(cpl->status.sct, SPDK_NVME_SCT_GENERIC);
	CU_ASSERT_EQUAL(cpl->status.sc, SPDK_NVME_SC_INVALID_FIELD);
	CU_ASSERT_EQUAL(cpl->status.dnr, 1);
	CU_ASSERT_EQUAL(qpair.state, SPDK_NVMF_QPAIR_ERROR);
	req.iov[0].iov_len = cmd.al = req.length = sizeof(*msg);

	nvmf_qpair_auth_destroy(&qpair);
}

int
main(int argc, char **argv)
{
	CU_pSuite suite = NULL;
	unsigned int num_failures;

	CU_initialize_registry();
	suite = CU_add_suite("nvmf_auth", NULL, NULL);
	CU_ADD_TEST(suite, test_auth_send_recv_error);
	CU_ADD_TEST(suite, test_auth_negotiate);
	CU_ADD_TEST(suite, test_auth_recv_failure1);

	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();

	free_threads();

	return num_failures;
}
