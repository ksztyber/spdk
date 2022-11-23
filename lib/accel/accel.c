/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2020 Intel Corporation.
 *   Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk_internal/accel_module.h"

#include "accel_internal.h"

#include "spdk/env.h"
#include "spdk/likely.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/json.h"
#include "spdk/crc32.h"
#include "spdk/util.h"

/* Accelerator Framework: The following provides a top level
 * generic API for the accelerator functions defined here. Modules,
 * such as the one in /module/accel/ioat, supply the implementation
 * with the exception of the pure software implementation contained
 * later in this file.
 */

#define ALIGN_4K			0x1000
#define MAX_TASKS_PER_CHANNEL		0x800

/* Largest context size for all accel modules */
static size_t g_max_accel_module_size = sizeof(struct spdk_accel_task);

static struct spdk_accel_module_if *g_accel_module = NULL;
static spdk_accel_fini_cb g_fini_cb_fn = NULL;
static void *g_fini_cb_arg = NULL;
static bool g_modules_started = false;

/* Global list of registered accelerator modules */
static TAILQ_HEAD(, spdk_accel_module_if) spdk_accel_module_list =
	TAILQ_HEAD_INITIALIZER(spdk_accel_module_list);

/* Global array mapping capabilities to modules */
static struct spdk_accel_module_if *g_modules_opc[ACCEL_OPC_LAST] = {};
static char *g_modules_opc_override[ACCEL_OPC_LAST] = {};

static const char *g_opcode_strings[ACCEL_OPC_LAST] = {
	"copy", "fill", "dualcast", "compare", "crc32c", "copy_crc32c",
	"compress", "decompress"
};

struct accel_io_channel {
	struct spdk_io_channel			*module_ch[ACCEL_OPC_LAST];
	void					*task_pool_base;
	struct spdk_accel_sequence		*seq_pool_base;
	TAILQ_HEAD(, spdk_accel_task)		task_pool;
	TAILQ_HEAD(, spdk_accel_sequence)	seq_pool;
};

TAILQ_HEAD(accel_sequence_tasks, spdk_accel_task);

struct spdk_accel_sequence {
	struct accel_io_channel			*ch;
	struct accel_sequence_tasks		tasks;
	struct accel_sequence_tasks		completed;
	spdk_accel_completion_cb		cb_fn;
	void					*cb_arg;
	TAILQ_ENTRY(spdk_accel_sequence)	link;
};

int
spdk_accel_get_opc_module_name(enum accel_opcode opcode, const char **module_name)
{
	if (opcode >= ACCEL_OPC_LAST) {
		/* invalid opcode */
		return -EINVAL;
	}

	if (g_modules_opc[opcode]) {
		*module_name = g_modules_opc[opcode]->name;
	} else {
		return -ENOENT;
	}

	return 0;
}

void
_accel_for_each_module(struct module_info *info, _accel_for_each_module_fn fn)
{
	struct spdk_accel_module_if *accel_module;
	enum accel_opcode opcode;
	int j = 0;

	TAILQ_FOREACH(accel_module, &spdk_accel_module_list, tailq) {
		for (opcode = 0; opcode < ACCEL_OPC_LAST; opcode++) {
			if (accel_module->supports_opcode(opcode)) {
				info->ops[j] = opcode;
				j++;
			}
		}
		info->name = accel_module->name;
		info->num_ops = j;
		fn(info);
		j = 0;
	}
}

int
_accel_get_opc_name(enum accel_opcode opcode, const char **opcode_name)
{
	int rc = 0;

	if (opcode < ACCEL_OPC_LAST) {
		*opcode_name = g_opcode_strings[opcode];
	} else {
		/* invalid opcode */
		rc = -EINVAL;
	}

	return rc;
}

int
spdk_accel_assign_opc(enum accel_opcode opcode, const char *name)
{
	if (g_modules_started == true) {
		/* we don't allow re-assignment once things have started */
		return -EINVAL;
	}

	if (opcode >= ACCEL_OPC_LAST) {
		/* invalid opcode */
		return -EINVAL;
	}

	/* module selection will be validated after the framework starts. */
	g_modules_opc_override[opcode] = strdup(name);

	return 0;
}

void
spdk_accel_task_complete(struct spdk_accel_task *accel_task, int status)
{
	struct accel_io_channel *accel_ch = accel_task->accel_ch;
	spdk_accel_completion_cb	cb_fn = accel_task->cb_fn;
	void				*cb_arg = accel_task->cb_arg;

	/* We should put the accel_task into the list firstly in order to avoid
	 * the accel task list is exhausted when there is recursive call to
	 * allocate accel_task in user's call back function (cb_fn)
	 */
	TAILQ_INSERT_HEAD(&accel_ch->task_pool, accel_task, link);

	cb_fn(cb_arg, status);
}

inline static struct spdk_accel_task *
_get_task(struct accel_io_channel *accel_ch, spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct spdk_accel_task *accel_task;

	accel_task = TAILQ_FIRST(&accel_ch->task_pool);
	if (accel_task == NULL) {
		return NULL;
	}

	TAILQ_REMOVE(&accel_ch->task_pool, accel_task, link);
	accel_task->link.tqe_next = NULL;
	accel_task->link.tqe_prev = NULL;

	accel_task->cb_fn = cb_fn;
	accel_task->cb_arg = cb_arg;
	accel_task->accel_ch = accel_ch;

	return accel_task;
}



/* Accel framework public API for copy function */
int
spdk_accel_submit_copy(struct spdk_io_channel *ch, void *dst, void *src,
		       uint64_t nbytes, int flags, spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_COPY];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_COPY];

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->dst = dst;
	accel_task->src = src;
	accel_task->op_code = ACCEL_OPC_COPY;
	accel_task->nbytes = nbytes;
	accel_task->flags = flags;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for dual cast copy function */
int
spdk_accel_submit_dualcast(struct spdk_io_channel *ch, void *dst1,
			   void *dst2, void *src, uint64_t nbytes, int flags,
			   spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_DUALCAST];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_DUALCAST];

	if ((uintptr_t)dst1 & (ALIGN_4K - 1) || (uintptr_t)dst2 & (ALIGN_4K - 1)) {
		SPDK_ERRLOG("Dualcast requires 4K alignment on dst addresses\n");
		return -EINVAL;
	}

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->src = src;
	accel_task->dst = dst1;
	accel_task->dst2 = dst2;
	accel_task->nbytes = nbytes;
	accel_task->flags = flags;
	accel_task->op_code = ACCEL_OPC_DUALCAST;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for compare function */
int
spdk_accel_submit_compare(struct spdk_io_channel *ch, void *src1,
			  void *src2, uint64_t nbytes, spdk_accel_completion_cb cb_fn,
			  void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_COMPARE];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_COMPARE];

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->src = src1;
	accel_task->src2 = src2;
	accel_task->nbytes = nbytes;
	accel_task->op_code = ACCEL_OPC_COMPARE;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for fill function */
int
spdk_accel_submit_fill(struct spdk_io_channel *ch, void *dst,
		       uint8_t fill, uint64_t nbytes, int flags,
		       spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_FILL];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_FILL];

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->dst = dst;
	memset(&accel_task->fill_pattern, fill, sizeof(uint64_t));
	accel_task->nbytes = nbytes;
	accel_task->flags = flags;
	accel_task->op_code = ACCEL_OPC_FILL;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for CRC-32C function */
int
spdk_accel_submit_crc32c(struct spdk_io_channel *ch, uint32_t *crc_dst,
			 void *src, uint32_t seed, uint64_t nbytes, spdk_accel_completion_cb cb_fn,
			 void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_CRC32C];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_CRC32C];

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->crc_dst = crc_dst;
	accel_task->src = src;
	accel_task->s.iovcnt = 0;
	accel_task->seed = seed;
	accel_task->nbytes = nbytes;
	accel_task->op_code = ACCEL_OPC_CRC32C;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for chained CRC-32C function */
int
spdk_accel_submit_crc32cv(struct spdk_io_channel *ch, uint32_t *crc_dst,
			  struct iovec *iov, uint32_t iov_cnt, uint32_t seed,
			  spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_CRC32C];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_CRC32C];

	if (iov == NULL) {
		SPDK_ERRLOG("iov should not be NULL");
		return -EINVAL;
	}

	if (!iov_cnt) {
		SPDK_ERRLOG("iovcnt should not be zero value\n");
		return -EINVAL;
	}

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		SPDK_ERRLOG("no memory\n");
		assert(0);
		return -ENOMEM;
	}

	accel_task->s.iovs = iov;
	accel_task->s.iovcnt = iov_cnt;
	accel_task->crc_dst = crc_dst;
	accel_task->seed = seed;
	accel_task->op_code = ACCEL_OPC_CRC32C;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for copy with CRC-32C function */
int
spdk_accel_submit_copy_crc32c(struct spdk_io_channel *ch, void *dst,
			      void *src, uint32_t *crc_dst, uint32_t seed, uint64_t nbytes,
			      int flags, spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_COPY_CRC32C];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_COPY_CRC32C];

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->dst = dst;
	accel_task->src = src;
	accel_task->crc_dst = crc_dst;
	accel_task->s.iovcnt = 0;
	accel_task->seed = seed;
	accel_task->nbytes = nbytes;
	accel_task->flags = flags;
	accel_task->op_code = ACCEL_OPC_COPY_CRC32C;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

/* Accel framework public API for chained copy + CRC-32C function */
int
spdk_accel_submit_copy_crc32cv(struct spdk_io_channel *ch, void *dst,
			       struct iovec *src_iovs, uint32_t iov_cnt, uint32_t *crc_dst,
			       uint32_t seed, int flags, spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_COPY_CRC32C];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_COPY_CRC32C];
	uint64_t nbytes;
	uint32_t i;

	if (src_iovs == NULL) {
		SPDK_ERRLOG("iov should not be NULL");
		return -EINVAL;
	}

	if (!iov_cnt) {
		SPDK_ERRLOG("iovcnt should not be zero value\n");
		return -EINVAL;
	}

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		SPDK_ERRLOG("no memory\n");
		assert(0);
		return -ENOMEM;
	}

	nbytes = 0;
	for (i = 0; i < iov_cnt; i++) {
		nbytes += src_iovs[i].iov_len;
	}

	accel_task->s.iovs = src_iovs;
	accel_task->s.iovcnt = iov_cnt;
	accel_task->dst = (void *)dst;
	accel_task->crc_dst = crc_dst;
	accel_task->seed = seed;
	accel_task->nbytes = nbytes;
	accel_task->flags = flags;
	accel_task->op_code = ACCEL_OPC_COPY_CRC32C;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);
}

int
spdk_accel_submit_compress(struct spdk_io_channel *ch, void *dst, uint64_t nbytes,
			   struct iovec *src_iovs, size_t src_iovcnt, uint32_t *output_size, int flags,
			   spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_COMPRESS];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_COMPRESS];
	size_t i, src_len = 0;

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	for (i = 0; i < src_iovcnt; i++) {
		src_len +=  src_iovs[i].iov_len;
	}

	accel_task->nbytes = src_len;
	accel_task->output_size = output_size;
	accel_task->s.iovs = src_iovs;
	accel_task->s.iovcnt = src_iovcnt;
	accel_task->dst = dst;
	accel_task->nbytes_dst = nbytes;
	accel_task->flags = flags;
	accel_task->op_code = ACCEL_OPC_COMPRESS;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);

	return 0;
}

int
spdk_accel_submit_decompress(struct spdk_io_channel *ch, struct iovec *dst_iovs,
			     size_t dst_iovcnt, struct iovec *src_iovs, size_t src_iovcnt,
			     int flags, spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *accel_task;
	struct spdk_accel_module_if *module = g_modules_opc[ACCEL_OPC_DECOMPRESS];
	struct spdk_io_channel *module_ch = accel_ch->module_ch[ACCEL_OPC_DECOMPRESS];

	accel_task = _get_task(accel_ch, cb_fn, cb_arg);
	if (accel_task == NULL) {
		return -ENOMEM;
	}

	accel_task->s.iovs = src_iovs;
	accel_task->s.iovcnt = src_iovcnt;
	accel_task->d.iovs = dst_iovs;
	accel_task->d.iovcnt = dst_iovcnt;
	accel_task->flags = flags;
	accel_task->op_code = ACCEL_OPC_DECOMPRESS;
	accel_task->src_domain = NULL;
	accel_task->dst_domain = NULL;

	return module->submit_tasks(module_ch, accel_task);

	return 0;
}

static inline struct spdk_accel_sequence *
accel_sequence_get(struct accel_io_channel *ch)
{
	struct spdk_accel_sequence *seq;

	seq = TAILQ_FIRST(&ch->seq_pool);
	if (seq == NULL) {
		return NULL;
	}

	TAILQ_REMOVE(&ch->seq_pool, seq, link);

	TAILQ_INIT(&seq->tasks);
	TAILQ_INIT(&seq->completed);

	seq->ch = ch;

	return seq;
}

static inline void
accel_sequence_put(struct spdk_accel_sequence *seq)
{
	struct accel_io_channel *ch = seq->ch;

	TAILQ_INSERT_HEAD(&ch->seq_pool, seq, link);
}

static void accel_sequence_task_cb(void *cb_arg, int status);

static inline struct spdk_accel_task *
accel_sequence_get_task(struct accel_io_channel *ch, struct spdk_accel_sequence *seq,
			spdk_accel_part_cb cb_fn, void *cb_arg)
{
	struct spdk_accel_task *task;

	task = _get_task(ch, accel_sequence_task_cb, seq);
	if (task == NULL) {
		return task;
	}

	task->part_cb_fn = cb_fn;
	task->part_cb_arg = cb_arg;

	return task;
}

int
spdk_accel_append_copy(struct spdk_accel_sequence **pseq, struct spdk_io_channel *ch,
		       struct iovec *dst_iovs, uint32_t dst_iovcnt,
		       struct spdk_memory_domain *dst_domain, void *dst_domain_ctx,
		       struct iovec *src_iovs, uint32_t src_iovcnt,
		       struct spdk_memory_domain *src_domain, void *src_domain_ctx,
		       int flags, spdk_accel_part_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *task;
	struct spdk_accel_sequence *seq = *pseq;

	if (dst_domain != NULL || src_domain != NULL) {
		SPDK_ERRLOG("Memory domains are currently unsupported\n");
		return -EINVAL;
	}

	if (seq == NULL) {
		seq = accel_sequence_get(accel_ch);
		if (spdk_unlikely(seq == NULL)) {
			return -ENOMEM;
		}
	}

	assert(seq->ch == accel_ch);
	task = accel_sequence_get_task(accel_ch, seq, cb_fn, cb_arg);
	if (spdk_unlikely(task == NULL)) {
		if (*pseq == NULL) {
			accel_sequence_put(seq);
		}

		return -ENOMEM;
	}

	task->dst_domain = dst_domain;
	task->dst_domain_ctx = dst_domain_ctx;
	task->d.iovs = dst_iovs;
	task->d.iovcnt = dst_iovcnt;
	task->src_domain = src_domain;
	task->src_domain_ctx = src_domain_ctx;
	task->s.iovs = src_iovs;
	task->s.iovcnt = src_iovcnt;
	task->flags = flags;
	task->op_code = ACCEL_OPC_COPY;

	TAILQ_INSERT_TAIL(&seq->tasks, task, seq_link);
	*pseq = seq;

	return 0;
}

int
spdk_accel_append_fill(struct spdk_accel_sequence **pseq, struct spdk_io_channel *ch,
		       void *buf, uint64_t len,
		       struct spdk_memory_domain *domain, void *domain_ctx, uint8_t pattern,
		       int flags, spdk_accel_part_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *task;
	struct spdk_accel_sequence *seq = *pseq;

	if (domain != NULL) {
		SPDK_ERRLOG("Memory domains are currently unsupported\n");
		return -EINVAL;
	}

	if (seq == NULL) {
		seq = accel_sequence_get(accel_ch);
		if (spdk_unlikely(seq == NULL)) {
			return -ENOMEM;
		}
	}

	assert(seq->ch == accel_ch);
	task = accel_sequence_get_task(accel_ch, seq, cb_fn, cb_arg);
	if (spdk_unlikely(task == NULL)) {
		if (*pseq == NULL) {
			accel_sequence_put(seq);
		}

		return -ENOMEM;
	}

	memset(&task->fill_pattern, pattern, sizeof(uint64_t));

	task->src_domain = NULL;
	task->dst_domain = domain;
	task->dst_domain_ctx = domain_ctx;
	task->dst = buf;
	task->nbytes = len;
	task->flags = flags;
	task->op_code = ACCEL_OPC_FILL;

	TAILQ_INSERT_TAIL(&seq->tasks, task, seq_link);
	*pseq = seq;

	return 0;
}

int
spdk_accel_append_decompress(struct spdk_accel_sequence **pseq, struct spdk_io_channel *ch,
			     struct iovec *dst_iovs, size_t dst_iovcnt,
			     struct spdk_memory_domain *dst_domain, void *dst_domain_ctx,
			     struct iovec *src_iovs, size_t src_iovcnt,
			     struct spdk_memory_domain *src_domain, void *src_domain_ctx,
			     int flags, spdk_accel_part_cb cb_fn, void *cb_arg)
{
	struct accel_io_channel *accel_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_accel_task *task;
	struct spdk_accel_sequence *seq = *pseq;

	if (dst_domain != NULL || src_domain != NULL) {
		SPDK_ERRLOG("Memory domains are currently unsupported\n");
		return -EINVAL;
	}

	if (seq == NULL) {
		seq = accel_sequence_get(accel_ch);
		if (spdk_unlikely(seq == NULL)) {
			return -ENOMEM;
		}
	}

	assert(seq->ch == accel_ch);
	task = accel_sequence_get_task(accel_ch, seq, cb_fn, cb_arg);
	if (spdk_unlikely(task == NULL)) {
		if (*pseq == NULL) {
			accel_sequence_put(seq);
		}

		return -ENOMEM;
	}

	task->dst_domain = dst_domain;
	task->dst_domain_ctx = dst_domain_ctx;
	task->d.iovs = dst_iovs;
	task->d.iovcnt = dst_iovcnt;
	task->src_domain = src_domain;
	task->src_domain_ctx = src_domain_ctx;
	task->s.iovs = src_iovs;
	task->s.iovcnt = src_iovcnt;
	task->flags = flags;
	task->op_code = ACCEL_OPC_DECOMPRESS;

	TAILQ_INSERT_TAIL(&seq->tasks, task, seq_link);
	*pseq = seq;

	return 0;
}

static void
accel_sequence_complete_tasks(struct spdk_accel_sequence *seq)
{
	struct spdk_accel_task *task;
	struct accel_io_channel *ch = seq->ch;
	spdk_accel_part_cb cb_fn;
	void *cb_arg;

	while (!TAILQ_EMPTY(&seq->completed)) {
		task = TAILQ_FIRST(&seq->completed);
		cb_fn = task->part_cb_fn;
		cb_arg = task->part_cb_arg;
		TAILQ_REMOVE(&seq->completed, task, seq_link);
		TAILQ_INSERT_HEAD(&ch->task_pool, task, link);
		if (cb_fn != NULL) {
			cb_fn(cb_arg);
		}
	}

	while (!TAILQ_EMPTY(&seq->tasks)) {
		task = TAILQ_FIRST(&seq->tasks);
		TAILQ_REMOVE(&seq->tasks, task, seq_link);
		cb_fn = task->part_cb_fn;
		cb_arg = task->part_cb_arg;
		TAILQ_INSERT_HEAD(&ch->task_pool, task, link);
		if (cb_fn != NULL) {
			cb_fn(cb_arg);
		}
	}
}

static void
accel_sequence_complete(struct spdk_accel_sequence *seq, int status)
{
	SPDK_DEBUGLOG(accel, "Completed sequence: %p with status: %d\n", seq, status);

	/* First notify all users that appended operations to this sequence */
	accel_sequence_complete_tasks(seq);

	/* Then notify the user that finished the sequence */
	seq->cb_fn(seq->cb_arg, status);

	accel_sequence_put(seq);
}

static void
accel_process_sequence(struct spdk_accel_sequence *seq)
{
	struct accel_io_channel *accel_ch = seq->ch;
	struct spdk_accel_module_if *module;
	struct spdk_io_channel *module_ch;
	struct spdk_accel_task *task;
	int rc;

	task = TAILQ_FIRST(&seq->tasks);
	if (task == NULL) {
		/* We've processed all tasks */
		accel_sequence_complete(seq, 0);
		return;
	}

	SPDK_DEBUGLOG(accel, "Executing %s operation, sequence: %p\n",
		      g_opcode_strings[task->op_code], seq);

	module = g_modules_opc[task->op_code];
	module_ch = accel_ch->module_ch[task->op_code];

	rc = module->submit_tasks(module_ch, task);
	if (spdk_unlikely(rc != 0)) {
		SPDK_ERRLOG("Failed to submit %s operation, sequence: %p\n",
			    g_opcode_strings[task->op_code], seq);
		accel_sequence_complete(seq, rc);
	}
}

static void
accel_sequence_task_cb(void *cb_arg, int status)
{
	struct spdk_accel_sequence *seq = cb_arg;
	struct spdk_accel_task *task = TAILQ_FIRST(&seq->tasks);
	struct accel_io_channel *accel_ch = seq->ch;

	/* spdk_accel_task_complete() puts the task back to the task pool, but we don't want to do
	 * that if a task is part of a sequence.  Removing the task from that pool here is the
	 * easiest way to prevent this, even though it is a bit hacky.
	 */
	assert(task != NULL);
	TAILQ_REMOVE(&accel_ch->task_pool, task, link);

	TAILQ_REMOVE(&seq->tasks, task, seq_link);
	TAILQ_INSERT_TAIL(&seq->completed, task, seq_link);

	if (spdk_unlikely(status != 0)) {
		SPDK_ERRLOG("Failed to execute %s operation, sequence: %p\n",
			    g_opcode_strings[task->op_code], seq);
		accel_sequence_complete(seq, status);
		return;
	}

	accel_process_sequence(seq);
}

static bool
accel_compare_iovs(struct iovec *iova, uint32_t iovacnt, struct iovec *iovb, uint32_t iovbcnt)
{
	/* For now, just do a dumb check that the iovecs arrays are exactly the same */
	if (iovacnt != iovbcnt) {
		return false;
	}

	return memcmp(iova, iovb, sizeof(*iova) * iovacnt) == 0;
}

static bool
accel_task_set_copy_buf(struct spdk_accel_task *task, struct spdk_accel_task *copy_task,
			bool destination)
{
	switch (task->op_code) {
	case ACCEL_OPC_COPY:
	case ACCEL_OPC_DECOMPRESS:
		if (destination) {
			if (task->dst_domain != copy_task->src_domain) {
				return false;
			}
			if (!accel_compare_iovs(task->d.iovs, task->d.iovcnt,
						copy_task->s.iovs, copy_task->s.iovcnt)) {
				return false;
			}
			task->d.iovs = copy_task->d.iovs;
			task->d.iovcnt = copy_task->d.iovcnt;
			task->dst_domain = copy_task->dst_domain;
		} else {
			if (task->src_domain != copy_task->dst_domain) {
				return false;
			}
			if (!accel_compare_iovs(task->s.iovs, task->s.iovcnt,
						copy_task->d.iovs, copy_task->d.iovcnt)) {
				return false;
			}
			task->s.iovs = copy_task->s.iovs;
			task->s.iovcnt = copy_task->s.iovcnt;
			task->src_domain = copy_task->src_domain;
		}
		break;
	case ACCEL_OPC_FILL:
		/* We don't change the buffers for operations that don't have distinct src/dst
		 * buffers.  Otherwise, we would need to change the buffers of other operations and
		 * it gets a lot more complex.
		 */
		return false;
	default:
		assert(0 && "bad opcode");
		break;
	}

	return true;
}

int
spdk_accel_sequence_finish(struct spdk_accel_sequence *seq,
			   spdk_accel_completion_cb cb_fn, void *cb_arg)
{
	struct spdk_accel_task *task, *next, *prev;

	/* Try to remove any copy operations if possible */
	TAILQ_FOREACH_SAFE(task, &seq->tasks, seq_link, next) {
		if (task->op_code != ACCEL_OPC_COPY) {
			continue;
		}

		prev = TAILQ_PREV(task, accel_sequence_tasks, seq_link);
		if (prev != NULL) {
			if (accel_task_set_copy_buf(prev, task, true)) {
				TAILQ_REMOVE(&seq->tasks, task, seq_link);
				TAILQ_INSERT_TAIL(&seq->completed, task, seq_link);
			}
		} else if (next != NULL) {
			if (accel_task_set_copy_buf(next, task, false)) {
				TAILQ_REMOVE(&seq->tasks, task, seq_link);
				TAILQ_INSERT_TAIL(&seq->completed, task, seq_link);
			}
		}
	}

	/* Since we store copy operations' buffers as iovecs, we need to convert them to scalar
	 * buffers, as that's what accel modules expect
	 */
	TAILQ_FOREACH(task, &seq->tasks, seq_link) {
		if (task->op_code != ACCEL_OPC_COPY) {
			continue;
		}

		if (spdk_unlikely(task->s.iovcnt != 1 || task->d.iovcnt != 1)) {
			SPDK_ERRLOG("Unable to set buffer of a copy operation due "
				    "to iovcnt!=1\n");
			return -EINVAL;
		}
		task->nbytes = spdk_min(task->s.iovs[0].iov_len,
					task->d.iovs[0].iov_len);
		task->src = task->s.iovs[0].iov_base;
		task->dst = task->d.iovs[0].iov_base;
	}

	seq->cb_fn = cb_fn;
	seq->cb_arg = cb_arg;

	accel_process_sequence(seq);

	return 0;
}

void
spdk_accel_sequence_reverse(struct spdk_accel_sequence *seq)
{
	struct accel_sequence_tasks tasks = TAILQ_HEAD_INITIALIZER(tasks);
	struct spdk_accel_task *task;

	assert(TAILQ_EMPTY(&seq->completed));
	TAILQ_SWAP(&tasks, &seq->tasks, spdk_accel_task, seq_link);

	while (!TAILQ_EMPTY(&tasks)) {
		task = TAILQ_FIRST(&tasks);
		TAILQ_REMOVE(&tasks, task, seq_link);
		TAILQ_INSERT_HEAD(&seq->tasks, task, seq_link);
	}
}

void
spdk_accel_sequence_abort(struct spdk_accel_sequence *seq)
{
	if (seq == NULL) {
		return;
	}

	accel_sequence_complete_tasks(seq);
	accel_sequence_put(seq);
}

static struct spdk_accel_module_if *
_module_find_by_name(const char *name)
{
	struct spdk_accel_module_if *accel_module = NULL;

	TAILQ_FOREACH(accel_module, &spdk_accel_module_list, tailq) {
		if (strcmp(name, accel_module->name) == 0) {
			break;
		}
	}

	return accel_module;
}

/* Helper function when when accel modules register with the framework. */
void
spdk_accel_module_list_add(struct spdk_accel_module_if *accel_module)
{
	if (_module_find_by_name(accel_module->name)) {
		SPDK_NOTICELOG("Accel module %s already registered\n", accel_module->name);
		assert(false);
		return;
	}

	/* Make sure that the software module is at the head of the list, this
	 * will assure that all opcodes are later assigned to software first and
	 * then udpated to HW modules as they are registered.
	 */
	if (strcmp(accel_module->name, "software") == 0) {
		TAILQ_INSERT_HEAD(&spdk_accel_module_list, accel_module, tailq);
	} else {
		TAILQ_INSERT_TAIL(&spdk_accel_module_list, accel_module, tailq);
	}

	if (accel_module->get_ctx_size && accel_module->get_ctx_size() > g_max_accel_module_size) {
		g_max_accel_module_size = accel_module->get_ctx_size();
	}
}

/* Framework level channel create callback. */
static int
accel_create_channel(void *io_device, void *ctx_buf)
{
	struct accel_io_channel	*accel_ch = ctx_buf;
	struct spdk_accel_task *accel_task;
	struct spdk_accel_sequence *seq;
	uint8_t *task_mem;
	int i = 0, j;

	accel_ch->task_pool_base = calloc(MAX_TASKS_PER_CHANNEL, g_max_accel_module_size);
	if (accel_ch->task_pool_base == NULL) {
		return -ENOMEM;
	}

	accel_ch->seq_pool_base = calloc(MAX_TASKS_PER_CHANNEL, sizeof(struct spdk_accel_sequence));
	if (accel_ch->seq_pool_base == NULL) {
		goto err;
	}

	TAILQ_INIT(&accel_ch->task_pool);
	TAILQ_INIT(&accel_ch->seq_pool);
	task_mem = accel_ch->task_pool_base;
	for (i = 0 ; i < MAX_TASKS_PER_CHANNEL; i++) {
		accel_task = (struct spdk_accel_task *)task_mem;
		seq = &accel_ch->seq_pool_base[i];
		TAILQ_INSERT_TAIL(&accel_ch->task_pool, accel_task, link);
		TAILQ_INSERT_TAIL(&accel_ch->seq_pool, seq, link);
		task_mem += g_max_accel_module_size;
	}

	/* Assign modules and get IO channels for each */
	for (i = 0; i < ACCEL_OPC_LAST; i++) {
		accel_ch->module_ch[i] = g_modules_opc[i]->get_io_channel();
		/* This can happen if idxd runs out of channels. */
		if (accel_ch->module_ch[i] == NULL) {
			goto err;
		}
	}

	return 0;
err:
	for (j = 0; j < i; j++) {
		spdk_put_io_channel(accel_ch->module_ch[j]);
	}
	free(accel_ch->task_pool_base);
	free(accel_ch->seq_pool_base);
	return -ENOMEM;
}

/* Framework level channel destroy callback. */
static void
accel_destroy_channel(void *io_device, void *ctx_buf)
{
	struct accel_io_channel	*accel_ch = ctx_buf;
	int i;

	for (i = 0; i < ACCEL_OPC_LAST; i++) {
		assert(accel_ch->module_ch[i] != NULL);
		spdk_put_io_channel(accel_ch->module_ch[i]);
		accel_ch->module_ch[i] = NULL;
	}

	free(accel_ch->task_pool_base);
	free(accel_ch->seq_pool_base);
}

struct spdk_io_channel *
spdk_accel_get_io_channel(void)
{
	return spdk_get_io_channel(&spdk_accel_module_list);
}

static void
accel_module_initialize(void)
{
	struct spdk_accel_module_if *accel_module;

	TAILQ_FOREACH(accel_module, &spdk_accel_module_list, tailq) {
		accel_module->module_init();
	}
}

int
spdk_accel_initialize(void)
{
	enum accel_opcode op;
	struct spdk_accel_module_if *accel_module = NULL;

	g_modules_started = true;
	accel_module_initialize();

	/* Create our priority global map of opcodes to modules, we populate starting
	 * with the software module (guaranteed to be first on the list) and then
	 * updating opcodes with HW modules that have been initilaized.
	 * NOTE: all opcodes must be suported by software in the event that no HW
	 * modules are initilaized to support the operation.
	 */
	TAILQ_FOREACH(accel_module, &spdk_accel_module_list, tailq) {
		for (op = 0; op < ACCEL_OPC_LAST; op++) {
			if (accel_module->supports_opcode(op)) {
				g_modules_opc[op] = accel_module;
				SPDK_DEBUGLOG(accel, "OPC 0x%x now assigned to %s\n", op, accel_module->name);
			}
		}
	}

	/* Now lets check for overrides and apply all that exist */
	for (op = 0; op < ACCEL_OPC_LAST; op++) {
		if (g_modules_opc_override[op] != NULL) {
			accel_module = _module_find_by_name(g_modules_opc_override[op]);
			if (accel_module == NULL) {
				SPDK_ERRLOG("Invalid module name of %s\n", g_modules_opc_override[op]);
				return -EINVAL;
			}
			if (accel_module->supports_opcode(op) == false) {
				SPDK_ERRLOG("Module %s does not support op code %d\n", accel_module->name, op);
				return -EINVAL;
			}
			g_modules_opc[op] = accel_module;
		}
	}

#ifdef DEBUG
	for (op = 0; op < ACCEL_OPC_LAST; op++) {
		assert(g_modules_opc[op] != NULL);
	}
#endif
	/*
	 * We need a unique identifier for the accel framework, so use the
	 * spdk_accel_module_list address for this purpose.
	 */
	spdk_io_device_register(&spdk_accel_module_list, accel_create_channel, accel_destroy_channel,
				sizeof(struct accel_io_channel), "accel");

	return 0;
}

static void
accel_module_finish_cb(void)
{
	spdk_accel_fini_cb cb_fn = g_fini_cb_fn;

	cb_fn(g_fini_cb_arg);
	g_fini_cb_fn = NULL;
	g_fini_cb_arg = NULL;
}

static void
accel_write_overridden_opc(struct spdk_json_write_ctx *w, const char *opc_str,
			   const char *module_str)
{
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "accel_assign_opc");
	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "opname", opc_str);
	spdk_json_write_named_string(w, "module", module_str);
	spdk_json_write_object_end(w);
	spdk_json_write_object_end(w);
}

void
spdk_accel_write_config_json(struct spdk_json_write_ctx *w)
{
	struct spdk_accel_module_if *accel_module;
	int i;

	/*
	 * The accel fw has no config, there may be some in
	 * the modules though.
	 */
	spdk_json_write_array_begin(w);
	TAILQ_FOREACH(accel_module, &spdk_accel_module_list, tailq) {
		if (accel_module->write_config_json) {
			accel_module->write_config_json(w);
		}
	}
	for (i = 0; i < ACCEL_OPC_LAST; i++) {
		if (g_modules_opc_override[i]) {
			accel_write_overridden_opc(w, g_opcode_strings[i], g_modules_opc_override[i]);
		}
	}
	spdk_json_write_array_end(w);
}

void
spdk_accel_module_finish(void)
{
	if (!g_accel_module) {
		g_accel_module = TAILQ_FIRST(&spdk_accel_module_list);
	} else {
		g_accel_module = TAILQ_NEXT(g_accel_module, tailq);
	}

	if (!g_accel_module) {
		accel_module_finish_cb();
		return;
	}

	if (g_accel_module->module_fini) {
		spdk_thread_send_msg(spdk_get_thread(), g_accel_module->module_fini, NULL);
	} else {
		spdk_accel_module_finish();
	}
}

void
spdk_accel_finish(spdk_accel_fini_cb cb_fn, void *cb_arg)
{
	enum accel_opcode op;

	assert(cb_fn != NULL);

	g_fini_cb_fn = cb_fn;
	g_fini_cb_arg = cb_arg;

	for (op = 0; op < ACCEL_OPC_LAST; op++) {
		if (g_modules_opc_override[op] != NULL) {
			free(g_modules_opc_override[op]);
			g_modules_opc_override[op] = NULL;
		}
		g_modules_opc[op] = NULL;
	}

	spdk_io_device_unregister(&spdk_accel_module_list, NULL);
	spdk_accel_module_finish();
}

SPDK_LOG_REGISTER_COMPONENT(accel)
