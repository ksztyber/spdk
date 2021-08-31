/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/trace.h"
#include "spdk/util.h"

struct spdk_trace_parser {
	struct spdk_trace_histories	*histories;
	size_t				map_size;
	int				fd;
};

static struct spdk_trace_parser *
init(const struct spdk_trace_parser_opts *opts)
{
	struct spdk_trace_parser *parser;
	struct stat stat;
	int rc;

	parser = (struct spdk_trace_parser *)calloc(1, sizeof(*parser));
	if (parser == NULL) {
		return NULL;
	}

	switch (opts->mode) {
	case SPDK_TRACE_PARSER_MODE_FILE:
		parser->fd = open(opts->filename, O_RDONLY);
		break;
	case SPDK_TRACE_PARSER_MODE_SHM:
		parser->fd = shm_open(opts->filename, O_RDONLY, 0600);
		break;
	default:
		SPDK_ERRLOG("Invalid mode: %d\n", opts->mode);
		parser->fd = -1;
		goto error;
	}

	if (parser->fd < 0) {
		SPDK_ERRLOG("Could not open trace file: %s (%d)\n", opts->filename, errno);
		goto error;
	}

	rc = fstat(parser->fd, &stat);
	if (rc < 0) {
		SPDK_ERRLOG("Could not get size of trace file: %s\n", opts->filename);
		goto error;
	}

	if ((size_t)stat.st_size < sizeof(*parser->histories)) {
		SPDK_ERRLOG("Invalid trace file: %s\n", opts->filename);
		goto error;
	}

	/* Map the header of trace file */
	parser->map_size = sizeof(*parser->histories);
	parser->histories = (struct spdk_trace_histories *)mmap(NULL, parser->map_size, PROT_READ,
			    MAP_SHARED, parser->fd, 0);
	if (parser->histories == MAP_FAILED) {
		SPDK_ERRLOG("Could not mmap trace file: %s\n", opts->filename);
		goto error;
	}

	/* Remap the entire trace file */
	parser->map_size = spdk_get_trace_histories_size(parser->histories);
	munmap(parser->histories, sizeof(*parser->histories));
	if ((size_t)stat.st_size < parser->map_size) {
		SPDK_ERRLOG("Trace file %s is not a valid\n", opts->filename);
		goto error;
	}
	parser->histories = (struct spdk_trace_histories *)mmap(NULL, parser->map_size, PROT_READ,
			    MAP_SHARED, parser->fd, 0);
	if (parser->histories == MAP_FAILED) {
		SPDK_ERRLOG("Could not mmap trace file: %s\n", opts->filename);
		goto error;
	}

	return parser;
error:
	spdk_trace_parser_cleanup(parser);
	return NULL;
}

static void
cleanup(struct spdk_trace_parser *parser)
{
	if (parser == NULL) {
		return;
	}

	if (parser->histories != NULL) {
		munmap(parser->histories, parser->map_size);
	}

	if (parser->fd > 0) {
		close(parser->fd);
	}

	free(parser);
}

extern "C" {

	struct spdk_trace_parser *
	spdk_trace_parser_init(const struct spdk_trace_parser_opts *opts)
	{
		return init(opts);
	}

	void
	spdk_trace_parser_cleanup(struct spdk_trace_parser *parser)
	{
		cleanup(parser);
	}

	void
	spdk_trace_parser_get_flags(struct spdk_trace_parser *parser,
				    struct spdk_trace_flags **flags)
	{
		*flags = &parser->histories->flags;
	}

} /* extern "C" */
