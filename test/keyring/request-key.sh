#!/usr/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Intel Corporation.  All rights reserved.

set -e

sn=$1 name=$2 keyring=$3
key="$(< "/tmp/$name")"

/usr/bin/keyctl instantiate "$sn" "$key" "$keyring"
