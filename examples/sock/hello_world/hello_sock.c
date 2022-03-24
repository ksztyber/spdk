/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 */

#include "spdk/assert.h"
#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"

#include "spdk/sock.h"

#define ACCEPT_TIMEOUT_US 1000
#define CLOSE_TIMEOUT_US 1000000
#define BUFFER_SIZE 1024
#define ADDR_STR_LEN INET6_ADDRSTRLEN

static bool g_is_running;

static char *g_host;
static char *g_sock_impl_name;
static int g_port;
static bool g_is_server;
static int g_zcopy;
static bool g_verbose;
static bool g_async;
static int g_bufsize = BUFFER_SIZE;

/*
 * We'll use this struct to gather housekeeping hello_context to pass between
 * our events and callbacks.
 */
struct hello_context_t {
	bool is_server;
	char *host;
	char *sock_impl_name;
	int port;
	int zcopy;
	int bufsize;

	bool verbose;
	int bytes_in;
	int bytes_out;

	struct spdk_sock *sock;

	struct spdk_sock_group *group;
	struct spdk_poller *poller_in;
	struct spdk_poller *poller_out;
	struct spdk_poller *time_out;

	int rc;
};

struct hello_client {
	struct spdk_sock_request	req;
	struct iovec			iov;
	struct spdk_sock		*sock;
	struct hello_context_t		*ctx;
	bool				busy;
	char				buf[BUFFER_SIZE];
};

/* There cannot be any padding between the request and the iovec */
SPDK_STATIC_ASSERT(offsetof(struct hello_client, iov) == sizeof(struct spdk_sock_request),
		   "Unexpected structure padding");

/*
 * Usage function for printing parameters that are specific to this application
 */
static void
hello_sock_usage(void)
{
	printf(" -H host_addr  host address\n");
	printf(" -P port       port number\n");
	printf(" -N sock_impl  socket implementation, e.g., -N posix or -N uring\n");
	printf(" -S            start in server mode\n");
	printf(" -V            print out additional informations\n");
	printf(" -z            disable zero copy send for the given sock implementation\n");
	printf(" -Z            enable zero copy send for the given sock implementation\n");
	printf(" -a            use asynchronous readv/writev interfaces\n");
	printf(" -b buffer_size buffer size to use for IOs\n");
}

/*
 * This function is called to parse the parameters that are specific to this application
 */
static int hello_sock_parse_arg(int ch, char *arg)
{
	switch (ch) {
	case 'H':
		g_host = arg;
		break;
	case 'N':
		g_sock_impl_name = arg;
		break;
	case 'P':
		g_port = spdk_strtol(arg, 10);
		if (g_port < 0) {
			fprintf(stderr, "Invalid port ID\n");
			return g_port;
		}
		break;
	case 'S':
		g_is_server = 1;
		break;
	case 'V':
		g_verbose = true;
		break;
	case 'Z':
		g_zcopy = 1;
		break;
	case 'z':
		g_zcopy = 0;
		break;
	case 'a':
		g_async = true;
		break;
	case 'b':
		g_bufsize = spdk_strtol(arg, 10);
		if (g_bufsize < 1 || g_bufsize > BUFFER_SIZE) {
			fprintf(stderr, "Invalid buffer size, must be between 1-%d bytes\n",
				BUFFER_SIZE);
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int
hello_sock_close_timeout_poll(void *arg)
{
	struct hello_context_t *ctx = arg;
	SPDK_NOTICELOG("Connection closed\n");

	spdk_poller_unregister(&ctx->time_out);
	spdk_poller_unregister(&ctx->poller_in);
	spdk_sock_close(&ctx->sock);
	spdk_sock_group_close(&ctx->group);

	spdk_app_stop(ctx->rc);
	return SPDK_POLLER_BUSY;
}

static int
hello_sock_quit(struct hello_context_t *ctx, int rc)
{
	ctx->rc = rc;
	spdk_poller_unregister(&ctx->poller_out);
	if (!ctx->time_out) {
		ctx->time_out = SPDK_POLLER_REGISTER(hello_sock_close_timeout_poll, ctx,
						     CLOSE_TIMEOUT_US);
	}
	return 0;
}

static int
hello_sock_recv_poll(void *arg)
{
	struct hello_context_t *ctx = arg;
	int rc;
	char buf_in[BUFFER_SIZE];

	/*
	 * Get response
	 */
	rc = spdk_sock_recv(ctx->sock, buf_in, ctx->bufsize - 1);

	if (rc <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return SPDK_POLLER_IDLE;
		}

		SPDK_ERRLOG("spdk_sock_recv() failed, errno %d: %s\n",
			    errno, spdk_strerror(errno));
		return SPDK_POLLER_BUSY;
	}

	if (rc > 0) {
		ctx->bytes_in += rc;
		buf_in[rc] = '\0';
		printf("%s", buf_in);
	}

	return SPDK_POLLER_BUSY;
}

static int
hello_sock_writev_poll(void *arg)
{
	struct hello_context_t *ctx = arg;
	int rc = 0;
	char buf_out[BUFFER_SIZE];
	struct iovec iov;
	ssize_t n;

	n = read(STDIN_FILENO, buf_out, ctx->bufsize);
	if (n == 0 || !g_is_running) {
		/* EOF */
		SPDK_NOTICELOG("Closing connection...\n");
		hello_sock_quit(ctx, 0);
		return SPDK_POLLER_IDLE;
	}
	if (n > 0) {
		/*
		 * Send message to the server
		 */
		iov.iov_base = buf_out;
		iov.iov_len = n;
		rc = spdk_sock_writev(ctx->sock, &iov, 1);
		if (rc > 0) {
			ctx->bytes_out += rc;
		}
	}
	return rc > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int
hello_sock_connect(struct hello_context_t *ctx)
{
	int rc;
	char saddr[ADDR_STR_LEN], caddr[ADDR_STR_LEN];
	uint16_t cport, sport;
	struct spdk_sock_opts opts;

	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.zcopy = ctx->zcopy;

	SPDK_NOTICELOG("Connecting to the server on %s:%d with sock_impl(%s)\n", ctx->host, ctx->port,
		       ctx->sock_impl_name);

	ctx->sock = spdk_sock_connect_ext(ctx->host, ctx->port, ctx->sock_impl_name, &opts);
	if (ctx->sock == NULL) {
		SPDK_ERRLOG("connect error(%d): %s\n", errno, spdk_strerror(errno));
		return -1;
	}

	rc = spdk_sock_getaddr(ctx->sock, saddr, sizeof(saddr), &sport, caddr, sizeof(caddr), &cport);
	if (rc < 0) {
		SPDK_ERRLOG("Cannot get connection addresses\n");
		spdk_sock_close(&ctx->sock);
		return -1;
	}

	SPDK_NOTICELOG("Connection accepted from (%s, %hu) to (%s, %hu)\n", caddr, cport, saddr, sport);

	fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);

	g_is_running = true;
	ctx->poller_in = SPDK_POLLER_REGISTER(hello_sock_recv_poll, ctx, 0);
	ctx->poller_out = SPDK_POLLER_REGISTER(hello_sock_writev_poll, ctx, 0);

	return 0;
}

static void
hello_sock_cb(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock)
{
	ssize_t n;
	char buf[BUFFER_SIZE];
	struct iovec iov;
	struct hello_context_t *ctx = arg;

	n = spdk_sock_recv(sock, buf, ctx->bufsize);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			SPDK_ERRLOG("spdk_sock_recv() failed, errno %d: %s\n",
				    errno, spdk_strerror(errno));
			return;
		}

		SPDK_ERRLOG("spdk_sock_recv() failed, errno %d: %s\n",
			    errno, spdk_strerror(errno));
	}

	if (n > 0) {
		ctx->bytes_in += n;
		iov.iov_base = buf;
		iov.iov_len = n;
		n = spdk_sock_writev(sock, &iov, 1);
		if (n > 0) {
			ctx->bytes_out += n;
		}
		return;
	}

	/* Connection closed */
	SPDK_NOTICELOG("Connection closed\n");
	spdk_sock_group_remove_sock(group, sock);
	spdk_sock_close(&sock);
}

static void
free_client(struct hello_client *client)
{
	spdk_sock_group_remove_sock(client->ctx->group, client->sock);
	spdk_sock_close(&client->sock);
	free(client);
}

static void
hello_sock_async_writev_cb(void *client_ctx, int status)
{
	struct hello_client *client = client_ctx;
	struct hello_context_t *ctx = client->ctx;

	if (status != 0) {
		SPDK_NOTICELOG("Connection closed\n");
		free_client(client);
		return;
	}

	ctx->bytes_out += client->iov.iov_len;
	client->busy = false;
}

static void
hello_sock_async_readv_cb(void *client_ctx, int status)
{
	struct hello_client *client = client_ctx;
	struct hello_context_t *ctx = client->ctx;

	if (status <= 0) {
		SPDK_NOTICELOG("Connection closed\n");
		free_client(client);
		return;
	}

	ctx->bytes_in += status;
	client->iov.iov_len = status;
	client->req.cb_fn = hello_sock_async_writev_cb;

	spdk_sock_writev_async(client->sock, &client->req);
}

static void
hello_sock_async_cb(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock)
{
	struct hello_client *client = arg;

	/* A request is already being serviced */
	if (client->busy) {
		return;
	}

	client->busy = true;
	client->iov.iov_len = client->ctx->bufsize;
	client->req.cb_fn = hello_sock_async_readv_cb;

	spdk_sock_readv_async(sock, &client->req);
}

static int
hello_sock_accept_client(struct hello_context_t *ctx, struct spdk_sock *sock)
{
	struct hello_client *client;
	int rc;

	if (!g_async) {
		return spdk_sock_group_add_sock(ctx->group, sock, hello_sock_cb, ctx);
	}

	client = calloc(1, sizeof(*client));
	if (!client) {
		return -ENOMEM;
	}

	client->sock = sock;
	client->ctx = ctx;
	client->req.iovcnt = 1;
	client->req.cb_fn = hello_sock_async_readv_cb;
	client->req.cb_arg = client;
	client->iov.iov_base = client->buf;
	client->iov.iov_len = ctx->bufsize;

	rc = spdk_sock_group_add_sock(ctx->group, sock, hello_sock_async_cb, client);
	if (rc != 0) {
		free(client);
		return rc;
	}

	return 0;
}

static int
hello_sock_accept_poll(void *arg)
{
	struct hello_context_t *ctx = arg;
	struct spdk_sock *sock;
	int rc;
	int count = 0;
	char saddr[ADDR_STR_LEN], caddr[ADDR_STR_LEN];
	uint16_t cport, sport;

	if (!g_is_running) {
		hello_sock_quit(ctx, 0);
		return SPDK_POLLER_IDLE;
	}

	while (1) {
		sock = spdk_sock_accept(ctx->sock);
		if (sock != NULL) {
			rc = spdk_sock_getaddr(sock, saddr, sizeof(saddr), &sport, caddr, sizeof(caddr), &cport);
			if (rc < 0) {
				SPDK_ERRLOG("Cannot get connection addresses\n");
				spdk_sock_close(&ctx->sock);
				return SPDK_POLLER_IDLE;
			}

			rc = spdk_sock_set_recvbuf(sock, BUFFER_SIZE);
			if (rc != 0) {
				SPDK_ERRLOG("Failed to set the receive buffer size\n");
				spdk_sock_close(&ctx->sock);
				return SPDK_POLLER_IDLE;
			}

			SPDK_NOTICELOG("Accepting a new connection from (%s, %hu) to (%s, %hu)\n",
				       caddr, cport, saddr, sport);

			rc = hello_sock_accept_client(ctx, sock);
			if (rc < 0) {
				spdk_sock_close(&sock);
				SPDK_ERRLOG("failed\n");
				break;
			}

			count++;
		} else {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				SPDK_ERRLOG("accept error(%d): %s\n", errno, spdk_strerror(errno));
			}
			break;
		}
	}

	return count > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int
hello_sock_group_poll(void *arg)
{
	struct hello_context_t *ctx = arg;
	int rc;

	rc = spdk_sock_group_poll(ctx->group);
	if (rc < 0) {
		SPDK_ERRLOG("Failed to poll sock_group=%p\n", ctx->group);
	}

	return rc > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int
hello_sock_listen(struct hello_context_t *ctx)
{
	struct spdk_sock_opts opts;

	opts.opts_size = sizeof(opts);
	spdk_sock_get_default_opts(&opts);
	opts.zcopy = ctx->zcopy;

	ctx->sock = spdk_sock_listen_ext(ctx->host, ctx->port, ctx->sock_impl_name, &opts);
	if (ctx->sock == NULL) {
		SPDK_ERRLOG("Cannot create server socket\n");
		return -1;
	}

	SPDK_NOTICELOG("Listening connection on %s:%d with sock_impl(%s)\n", ctx->host, ctx->port,
		       ctx->sock_impl_name);

	/*
	 * Create sock group for server socket
	 */
	ctx->group = spdk_sock_group_create(NULL);

	g_is_running = true;

	/*
	 * Start acceptor and group poller
	 */
	ctx->poller_in = SPDK_POLLER_REGISTER(hello_sock_accept_poll, ctx,
					      ACCEPT_TIMEOUT_US);
	ctx->poller_out = SPDK_POLLER_REGISTER(hello_sock_group_poll, ctx, 0);

	return 0;
}

static void
hello_sock_shutdown_cb(void)
{
	g_is_running = false;
}

/*
 * Our initial event that kicks off everything from main().
 */
static void
hello_start(void *arg1)
{
	struct hello_context_t *ctx = arg1;
	int rc;

	SPDK_NOTICELOG("Successfully started the application\n");

	if (ctx->is_server) {
		rc = hello_sock_listen(ctx);
	} else {
		rc = hello_sock_connect(ctx);
	}

	if (rc) {
		spdk_app_stop(-1);
		return;
	}
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc = 0;
	struct hello_context_t hello_context = {};

	/* Set default values in opts structure. */
	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "hello_sock";
	opts.shutdown_cb = hello_sock_shutdown_cb;

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "ab:H:N:P:SVzZ", NULL, hello_sock_parse_arg,
				      hello_sock_usage)) != SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}
	hello_context.is_server = g_is_server;
	hello_context.host = g_host;
	hello_context.sock_impl_name = g_sock_impl_name;
	hello_context.port = g_port;
	hello_context.zcopy = g_zcopy;
	hello_context.verbose = g_verbose;
	hello_context.bufsize = g_bufsize;

	rc = spdk_app_start(&opts, hello_start, &hello_context);
	if (rc) {
		SPDK_ERRLOG("ERROR starting application\n");
	}

	SPDK_NOTICELOG("Exiting from application\n");

	if (hello_context.verbose) {
		printf("** %d bytes received, %d bytes sent **\n",
		       hello_context.bytes_in, hello_context.bytes_out);
	}

	/* Gracefully close out all of the SPDK subsystems. */
	spdk_app_fini();
	return rc;
}
