#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Intel Corporation.  All rights reserved.
#

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../../")

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/nvmf/common.sh"

digests=("sha256" "sha384" "sha512")
# There's a bug in the kernel with the way dhgroups are selected that makes it impossible to select
# null dhgroup (i.e. skip DH part of the DH-HMAC-CHAP protocol).
dhgroups=("ffdhe2048" "ffdhe3072" "ffdhe4096" "ffdhe6144" "ffdhe8192")
subnqn="nqn.2024-02.io.spdk:cnode0"
hostnqn="nqn.2024-02.io.spdk:host0"
nvmet_subsys="/sys/kernel/config/nvmet/subsystems/$subnqn"
nvmet_host="/sys/kernel/config/nvmet/hosts/$hostnqn"
keys=()

cleanup() {
	nvmftestfini || :
	rmdir "$nvmet_host" || :
	clean_kernel_target || :
	for key in "${keys[@]}"; do
		rm -f "$key"
	done
	nvmetcli clear
}

nvmet_auth_init() {
	configure_kernel_target "$subnqn"
	mkdir "$nvmet_host"
	echo 0 > "$nvmet_subsys/attr_allow_any_host"
	ln -s "$nvmet_host" "$nvmet_subsys/allowed_hosts/$hostnqn"
}

nvmet_auth_set_key() {
	local digest dhgroup key

	digest="$1" dhgroup="$2" key="$3"

	echo "hmac($digest)" > "$nvmet_host/dhchap_hash"
	echo "$dhgroup" > "$nvmet_host/dhchap_dhgroup"
	echo "$key" > "$nvmet_host/dhchap_key"
}

gen_key() {
	local digest len file key
	local -A digests=([null]=0 [sha256]=1 [sha384]=2 [sha512]=3)

	digest="$1" len=$2
	key=$(xxd -p -c0 -l $((len / 2)) /dev/urandom)
	file=$(mktemp)
	format_chap_key "$key" "${digests[$1]}" > "$file"
	chmod 0600 "$file"

	echo "$file"
}

connect_authenticate() {
	local digest dhgroup keyid key

	digest="$1" dhgroup="$2" keyid="$3"
	key=$(< "${keys[keyid]}")

	nvmet_auth_set_key "$digest" "$dhgroup" "$key"
	rpc_cmd bdev_nvme_set_options --chap-digests "$digest" --chap-dhgroups "$dhgroup"
	rpc_cmd bdev_nvme_attach_controller -b nvme0 -t "$TEST_TRANSPORT" -f ipv4 \
		-a "$NVMF_INITIATOR_IP" -s "$NVMF_PORT" -q "$hostnqn" -n "$subnqn" \
		--chap-key "key${keyid}"
	[[ $(rpc_cmd bdev_nvme_get_controllers | jq -r '.[].name') == "nvme0" ]]
	rpc_cmd bdev_nvme_detach_controller nvme0
}

nvmftestinit
nvmfappstart -L nvme_auth

trap cleanup SIGINT SIGTERM EXIT

keys[0]=$(gen_key "null" 32)
keys[1]=$(gen_key "null" 48)
keys[2]=$(gen_key "sha256" 32)
keys[3]=$(gen_key "sha384" 48)
keys[4]=$(gen_key "sha512" 64)

waitforlisten "$nvmfpid"
for i in "${!keys[@]}"; do
	rpc_cmd keyring_add_key "key$i" keyfile --keyfile-path "${keys[i]}"
done

nvmet_auth_init
for digest in "${digests[@]}"; do
	for dhgroup in "${dhgroups[@]}"; do
		for key in "${!keys[@]}"; do
			connect_authenticate "$digest" "$dhgroup" "$key"
		done
	done
done

# Ensure that a missing key results in failed attach
nvmet_auth_set_key "sha256" "ffdhe2048" "$(< ${keys[0]})"
rpc_cmd bdev_nvme_set_options --chap-digests "sha256" --chap-dhgroups "ffdhe2048"
NOT rpc_cmd bdev_nvme_attach_controller -b nvme0 -t "$TEST_TRANSPORT" -f ipv4 \
		-a "$NVMF_INITIATOR_IP" -s "$NVMF_PORT" -q "$hostnqn" -n "$subnqn"
(($(rpc_cmd bdev_nvme_get_controllers | jq 'length') == 0))
# Check that mismatched keys result in failed attach
NOT rpc_cmd bdev_nvme_attach_controller -b nvme0 -t "$TEST_TRANSPORT" -f ipv4 \
		-a "$NVMF_INITIATOR_IP" -s "$NVMF_PORT" -q "$hostnqn" -n "$subnqn" \
		--chap-key "key1"
(($(rpc_cmd bdev_nvme_get_controllers | jq 'length') == 0))
