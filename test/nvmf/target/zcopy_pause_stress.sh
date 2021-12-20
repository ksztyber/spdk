#!/usr/bin/env bash

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)

source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

rpc_py="$rootdir/scripts/rpc.py"

nvmftestinit
nvmfappstart

if [ "$TEST_TRANSPORT" != tcp ]; then
	echo "Unsupported transport: $TEST_TRANSPORT"
	exit 0
fi

# Enable zero-copy and set in-capsule data size to zero to make sure all requests are using
# zero-copy
$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS -c 0 -z

$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode1 -a -s SPDK00000000000001 -m 10
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT \
	-a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT
$rpc_py bdev_malloc_create 32 4096 -b malloc0
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode1 malloc0 -n 1

# First, make sure data consistency is preserved by running verify
#$SPDK_EXAMPLE_DIR/perf -c 0x1 \
#	-r "trtype:$TEST_TRANSPORT adrfam:IPv4 traddr:$NVMF_FIRST_TARGET_IP trsvcid:$NVMF_PORT ns:1" \
#	-t 10 -q 128 -w verify -o 4096

# Then run perf in the background while pausing/resuming the subsystem to check that the requests
# are correctly queued and executed in this case.
#$SPDK_EXAMPLE_DIR/perf -c 0x2 \
#	-r "trtype:$TEST_TRANSPORT adrfam:IPv4 traddr:$NVMF_FIRST_TARGET_IP trsvcid:$NVMF_PORT ns:1" \
#	-t 20 -q 128 -w randread -o 4096 & perfpid=$!

#while kill -0 $perfpid; do
#	# Add the same namespace again.  It'll fail, but will also pause/resume the subsystem and
#	# the namespace forcing the IO requests to be queued/resubmitted.
#	$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode1 malloc0 -n 1 &>/dev/null || true
#done
#
#wait $perfpid

$SPDK_EXAMPLE_DIR/abort -c 0x2 \
	-r "trtype:$TEST_TRANSPORT adrfam:IPv4 traddr:$NVMF_FIRST_TARGET_IP trsvcid:$NVMF_PORT" \
	-t 1 -T all

trap - SIGINT SIGTERM EXIT
nvmftestfini
