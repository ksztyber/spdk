#!/usr/bin/env bash

set -e

testdir=$(readlink -f $(dirname $0))
rootdir=$testdir/../../..

source $rootdir/test/common/autotest_common.sh

export LD_LIBRARY_PATH=$testdir:$rootdir/build/lib:$rootdir/dpdk/build/lib

# Make sure all NVMe devices are reported if no address is specified
identify_data=$($testdir/identify)
for bdf in $(get_nvme_bdfs); do
	grep $bdf <<< $identify_data
done

# Verify that each device can be queried individually too
for bdf in $(get_nvme_bdfs); do
	$testdir/identify $bdf
done
