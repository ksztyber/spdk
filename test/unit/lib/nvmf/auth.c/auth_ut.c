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
DEFINE_STUB(spdk_nvmf_qpair_disconnect, int,
	    (struct spdk_nvmf_qpair *q, nvmf_qpair_disconnect_cb cb, void *c), 0);

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
	int rc;

	rc = nvmf_qpair_auth_init(&qpair);
	SPDK_CU_ASSERT_FATAL(rc == 0);

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

	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();

	free_threads();

	return num_failures;
}
