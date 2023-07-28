/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   Copyright (c) 2016 FUJITSU LIMITED, All rights reserved.
 */

#include "spdk_internal/cunit.h"

#include "bdev/scsi_nvme.c"

static int
null_init(void)
{
	return 0;
}

static int
null_clean(void)
{
	return 0;
}

static void
scsi_nvme_translate_test(void)
{
	struct spdk_bdev_io bdev_io;
	int sc, sk, asc, ascq;

	/* SPDK_NVME_SCT_GENERIC */
	bdev_io.internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_SUCCESS;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_GOOD);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_NO_SENSE);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_INVALID_OPCODE;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_INVALID_COMMAND_OPERATION_CODE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_INVALID_FIELD_IN_CDB);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_DATA_TRANSFER_ERROR;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MEDIUM_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_ABORTED_POWER_LOSS;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_TASK_ABORTED);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ABORTED_COMMAND);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_WARNING);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_POWER_LOSS_EXPECTED);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_HARDWARE_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_INTERNAL_TARGET_FAILURE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_ABORTED_BY_REQUEST;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_TASK_ABORTED);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ABORTED_COMMAND);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_INVALID_NAMESPACE_OR_FORMAT;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_ACCESS_DENIED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_INVALID_LU_IDENTIFIER);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_LBA_OUT_OF_RANGE;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_NAMESPACE_NOT_READY;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_NOT_READY);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_LOGICAL_UNIT_NOT_READY);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_RESERVATION_CONFLICT;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_RESERVATION_CONFLICT);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_NO_SENSE);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_INVALID_NUM_SGL_DESCIRPTORS;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	/* SPDK_NVME_SCT_COMMAND_SPECIFIC */
	bdev_io.internal.error.nvme.sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_COMPLETION_QUEUE_INVALID;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FORMAT;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_FORMAT_COMMAND_FAILED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_FORMAT_COMMAND_FAILED);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_CONFLICTING_ATTRIBUTES;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_INVALID_FIELD_IN_CDB);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_ATTEMPTED_WRITE_TO_RO_RANGE;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_DATA_PROTECT);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_WRITE_PROTECTED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_OVERLAPPING_RANGE;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	/* SPDK_NVME_SCT_MEDIA_ERROR */
	bdev_io.internal.error.nvme.sct = SPDK_NVME_SCT_MEDIA_ERROR;
	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_WRITE_FAULTS;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MEDIUM_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_PERIPHERAL_DEVICE_WRITE_FAULT);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_UNRECOVERED_READ_ERROR;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MEDIUM_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_UNRECOVERED_READ_ERROR);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_GUARD_CHECK_ERROR;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MEDIUM_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_LOGICAL_BLOCK_GUARD_CHECK_FAILED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_LOGICAL_BLOCK_GUARD_CHECK_FAILED);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_APPLICATION_TAG_CHECK_ERROR;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MEDIUM_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_LOGICAL_BLOCK_APP_TAG_CHECK_FAILED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_LOGICAL_BLOCK_APP_TAG_CHECK_FAILED);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_REFERENCE_TAG_CHECK_ERROR;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MEDIUM_ERROR);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_LOGICAL_BLOCK_REF_TAG_CHECK_FAILED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_LOGICAL_BLOCK_REF_TAG_CHECK_FAILED);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_COMPARE_FAILURE;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_MISCOMPARE);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_MISCOMPARE_DURING_VERIFY_OPERATION);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_ACCESS_DENIED;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_DATA_PROTECT);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_ACCESS_DENIED);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_NO_ACCESS_RIGHTS);

	bdev_io.internal.error.nvme.sc = SPDK_NVME_SC_DEALLOCATED_OR_UNWRITTEN_BLOCK;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);

	/* SPDK_NVME_SCT_VENDOR_SPECIFIC */
	bdev_io.internal.error.nvme.sct = SPDK_NVME_SCT_VENDOR_SPECIFIC;
	bdev_io.internal.error.nvme.sc = 0xff;
	spdk_scsi_nvme_translate(&bdev_io, &sc, &sk, &asc, &ascq);
	CU_ASSERT_EQUAL(sc, SPDK_SCSI_STATUS_CHECK_CONDITION);
	CU_ASSERT_EQUAL(sk, SPDK_SCSI_SENSE_ILLEGAL_REQUEST);
	CU_ASSERT_EQUAL(asc, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE);
	CU_ASSERT_EQUAL(ascq, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
}

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_set_error_action(CUEA_ABORT);
	CU_initialize_registry();

	suite = CU_add_suite("scsi_nvme_suite", null_init, null_clean);

	CU_ADD_TEST(suite, scsi_nvme_translate_test);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	num_failures = CU_get_number_of_failures();
	CU_cleanup_registry();
	return num_failures;
}
