# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Intel Corporation.  All rights reserved.

from .cmd_parser import *


def keyring_add_key(client, name, module, **kwargs):
    strip_globals(kwargs)
    remove_null(kwargs)
    return client.call('keyring_add_key', {'name': name,
                                           'module': module, **kwargs})


def keyring_remove_key(client, name):
    return client.call('keyring_remove_key', {'name': name})


def keyring_get_keys(client):
    return client.call('keyring_get_keys')


def keyring_linux_set_options(client, enable=None):
    params = {}
    if enable is not None:
        params['enable'] = enable
    return client.call('keyring_linux_set_options', params)
