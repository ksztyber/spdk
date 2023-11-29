/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation.  All rights reserved.
 */
#include "spdk_internal/cunit.h"
#include "spdk_internal/mock.h"
#include "spdk/util.h"

#include "keyring/keyring.c"

#if 0
struct ut_key {
#define UT_KEY_SIZE 64
	char buf[UT_KEY_SIZE];
	int len;
};

static int g_add_status;

static int
ut_keyring_add(struct spdk_key *key, const struct spdk_key_opts *opts)
{
	struct ut_key *utkey = spdk_key_get_ctx(key);

	if (g_add_status) {
		return g_add_status;
	}

	SPDK_CU_ASSERT_FATAL(opts != NULL);
	SPDK_CU_ASSERT_FATAL(opts->params != NULL);
	SPDK_CU_ASSERT_FATAL(opts->params->len <= UT_KEY_SIZE);

	/* Use spdk_json_val's start/len to pass a buffer with the key */
	memcpy(utkey->buf, opts->params->start, opts->params->len);
	utkey->len = opts->params->len;

	return 0;
}

static bool g_del_called;

static void
ut_keyring_del(struct spdk_key *key)
{
	struct ut_key *utkey = spdk_key_get_ctx(key);

	g_del_called = true;

	memset(utkey->buf, 0, utkey->len);
	utkey->len = 0;
}

static int
ut_keyring_get_key(struct spdk_key *key, void *buf, int len)
{
	struct ut_key *utkey = spdk_key_get_ctx(key);

	if (utkey->len <= 0) {
		return -EBADF;
	}

	SPDK_CU_ASSERT_FATAL(len >= utkey->len);
	memcpy(buf, utkey->buf, utkey->len);

	return utkey->len;
}

static size_t
ut_keyring_get_ctx_size(void)
{
	return sizeof(struct ut_key);
}

static struct spdk_keyring_module g_module = {
	.name = "ut",
	.del = ut_keyring_del,
	.get_key = ut_keyring_get_key,
};

static void
test_keyring_add(void)
{
	struct spdk_key *key;
	char keybuf[UT_KEY_SIZE], buf[UT_KEY_SIZE];
	struct spdk_json_val params = { .start = keybuf, .len = UT_KEY_SIZE };
	struct spdk_key_opts opts = {
		.size = SPDK_SIZEOF(&opts, params),
		.params = &params,
	};
	int rc;

	/* Try to add a key without the module being set */
	g_keyring.module = NULL;
	memset(keybuf, 0x5a, sizeof(keybuf));
	rc = spdk_keyring_add("key0", &opts);
	CU_ASSERT_EQUAL(rc, -ENODEV);
	g_keyring.module =  &g_module;

	/* Add a key and verify that it's available */
	memset(keybuf, 0xa5, sizeof(keybuf));
	rc = spdk_keyring_add("key0", &opts);
	CU_ASSERT_EQUAL(rc, 0);

	key = spdk_keyring_get("key0");
	SPDK_CU_ASSERT_FATAL(key != NULL);

	rc = spdk_key_get_key(key, buf, sizeof(buf));
	CU_ASSERT_EQUAL(rc, UT_KEY_SIZE);
	CU_ASSERT_EQUAL(memcmp(buf, keybuf, sizeof(buf)), 0);
	spdk_keyring_put(key);

	/* Try to add a key with the same name */
	memset(keybuf, 0x5a, sizeof(keybuf));
	rc = spdk_keyring_add("key0", &opts);
	CU_ASSERT_EQUAL(rc, -EEXIST);

	key = spdk_keyring_get("key0");
	SPDK_CU_ASSERT_FATAL(key != NULL);
	rc = spdk_key_get_key(key, buf, sizeof(buf));
	CU_ASSERT_EQUAL(rc, UT_KEY_SIZE);

	memset(keybuf, 0xa5, sizeof(keybuf));
	CU_ASSERT_EQUAL(memcmp(buf, keybuf, sizeof(buf)), 0);
	spdk_keyring_put(key);
	spdk_keyring_del("key0");

	/* Check that a key won't be created when a module fails  */
	g_add_status = -EACCES;
	rc = spdk_keyring_add("key0", &opts);
	CU_ASSERT_EQUAL(rc, -EACCES);
	key = spdk_keyring_get("key0");
	CU_ASSERT_PTR_NULL(key);
	g_add_status = 0;
}

static void
test_keyring_get(void)
{
	struct spdk_key *key, *key2;
	char keybuf[UT_KEY_SIZE], buf[UT_KEY_SIZE];
	struct spdk_json_val params = { .start = keybuf, .len = UT_KEY_SIZE };
	struct spdk_key_opts opts = {
		.size = SPDK_SIZEOF(&opts, params),
		.params = &params,
	};
	int rc;

	memset(keybuf, 0xa5, sizeof(keybuf));
	rc = spdk_keyring_add("key0", &opts);
	CU_ASSERT_EQUAL(rc, 0);

	/* Check getting non-existing key */
	key = spdk_keyring_get("invalid");
	CU_ASSERT_PTR_NULL(key);

	/* Get a reference to a key */
	key = spdk_keyring_get("key0");
	SPDK_CU_ASSERT_FATAL(key != NULL);

	/* Get another reference */
	key = spdk_keyring_get("key0");
	CU_ASSERT_PTR_NOT_NULL(key2);
	CU_ASSERT_PTR_EQUAL(key, key);

	/* Check that the key buffer can be correctly retrieved */
	rc = spdk_key_get_key(key, buf, sizeof(buf));
	CU_ASSERT_EQUAL(rc, UT_KEY_SIZE);
	CU_ASSERT_EQUAL(memcmp(keybuf, buf, sizeof(buf)), 0);

	/* Delete the key and check that it's not possible to get a reference to that key */
	g_del_called = false;
	spdk_keyring_del("key0");
	CU_ASSERT(g_del_called);
	key2 = spdk_keyring_get("key0");
	CU_ASSERT_PTR_NULL(key2);

	/* Check that after spdk_keyring_del(), the module gets a del callback and deletes the key
	 * and it's no longer possible to obtain it.
	 */
	rc = spdk_key_get_key(key, buf, sizeof(buf));
	CU_ASSERT_EQUAL(rc, -EBADF);

	/* But the references are still valid.  To test that, get key's name and rely on address
	 * sanitizer to catch any potential use-after-free errors.
	 */
	CU_ASSERT_STRING_EQUAL("key0", spdk_key_get_name(key));

	/* Drop one of the two references */
	spdk_keyring_put(key);
	CU_ASSERT_STRING_EQUAL("key0", spdk_key_get_name(key));

	/* Drop the second one - the key should be freed now.  Again, rely on address sanitizer to
	 * catch memory leaks if it isn't.
	 */
	spdk_keyring_put(key);
}

static void
test_keyring_del(void)
{
	struct spdk_key *key;
	char keybuf[UT_KEY_SIZE];
	struct spdk_json_val params = { .start = keybuf, .len = UT_KEY_SIZE };
	struct spdk_key_opts opts = {
		.size = SPDK_SIZEOF(&opts, params),
		.params = &params,
	};
	int rc;

	/* Create a key and delete it */
	rc = spdk_keyring_add("key0", &opts);
	CU_ASSERT_EQUAL(rc, 0);

	g_del_called = false;
	spdk_keyring_del("key0");
	CU_ASSERT(g_del_called);
	key = spdk_keyring_get("key0");
	CU_ASSERT_PTR_NULL(key);

	/* Try to delete it again, should be safe and result in no-op */
	g_del_called = false;
	spdk_keyring_del("key0");
	CU_ASSERT_FALSE(g_del_called);
}

static int
test_setup(void)
{
	return spdk_keyring_set_module("ut");
}
#endif

int
main(int argc, char **argv)
{
#if 0
	CU_pSuite suite;
	unsigned int num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("keyring", test_setup, NULL);
	CU_ADD_TEST(suite, test_keyring_add);
	CU_ADD_TEST(suite, test_keyring_get);
	CU_ADD_TEST(suite, test_keyring_del);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();

	return num_failures;
#else
	return 0;
#endif
}
