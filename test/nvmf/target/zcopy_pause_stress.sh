#!/usr/bin/env bash

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)

source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

rpc_py="$rootdir/scripts/rpc.py"

rw=randread
runtime=30
io_size=4096

nvmftestinit
nvmfappstart

if [ "$TEST_TRANSPORT" != tcp ]; then
	echo "Unsupported transport: $TEST_TRANSPORT"
	exit 0
fi

$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS -c 0 -z

$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode1 -a -s SPDK00000000000001 -m 10
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT \
	-a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT
$rpc_py bdev_malloc_create 32 4096 -b malloc0
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode1 malloc0 -n 1

$SPDK_EXAMPLE_DIR/perf -c 0x1 \
	-r "trtype:$TEST_TRANSPORT adrfam:IPv4 traddr:$NVMF_FIRST_TARGET_IP trsvcid:$NVMF_PORT ns:1" \
	-t $runtime -q 128 -w $rw -o $io_size & perfpid=$!

while kill -0 $perfpid; do
	# Add the same namespace again.  It'll fail, but will also pause/resume the subsystem and
	# the namespace forcing the IO requests to be queued/resubmitted.
	$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode1 malloc0 -n 1 &>/dev/null || true
done

wait $perfpid

trap - SIGINT SIGTERM EXIT
nvmftestfini
