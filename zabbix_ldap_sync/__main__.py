#!/usr/bin/env python3
#
# Copyright (c) 2017-now Marc Schöchlin <ms@256bit.org>
# Copyright (c) 2013-2014 Marin Atanasov Nikolov <dnaeon@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer
#    in this position and unchanged.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
The zabbix-ldap-sync script is used for syncing LDAP users with Zabbix.

"""
import warnings
import traceback
import sys
import os
import logging
import argparse

from .zabbixldapconf import ZabbixLDAPConf
from .zabbixconn import ZabbixConn
from .ldapconn import LDAPConn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 0.1.1",
        help="Display version and exit")
    parser.add_argument("-l", "--lowercase", action="store_true",
        help="Create AD user names as lowercase")
    parser.add_argument("-r", "--recursive", action="store_true",
        help="Resolves AD group members recursively (i.e. nested groups)")
    parser.add_argument("-w", "--wildcard-search", action="store_true",
        help="Search AD group with wildcard (e.g. R.*.Zabbix.*) - TESTED ONLY with Active Directory")
    parser.add_argument("-d", "--delete-orphans", action="store_true",
        help="Delete Zabbix users that don't exist in a LDAP group")
    parser.add_argument("-n", "--no-check-certificate", action="store_true",
        help="Don't check Zabbix server certificate")
    parser.add_argument("--verbose", action="store_true",
        help="Print debug message from ZabbixAPI")
    parser.add_argument("--dryrun", action="store_true",
        help="Just simulate zabbix interaction")
    parser.add_argument("-f", "--file", required=True,
        help="Configuration file to use")

    disable_mode = parser.add_mutually_exclusive_group()
    disable_mode.add_argument("-s", "--skip-disabled", action="store_const",
        dest="disabled_mode", const="delete", default="disable",
        help="Old version of `--disabled-mode remove-groups`")
    disable_mode.add_argument("--disabled-mode", choices=["ignore", "remove-groups", "set-disabled"],
        dest="disabled_mode", default="disable",
        help="How to handle users disabled in LDAP/AD. `ignore` processes them as usual. `remove-groups` removes all of the managed groups from the user (which may cause them to be orphaned and deleted). `set-disabled` moves them to a disabled group.")

    parser.add_argument("--deleted-mode", choices=["ignore", "remove-groups", "set-disabled"],
        help="How to handle users that exist in Zabbix but not LDAP/AD. Choices and actions are the same as --disabled-mode")

    args = parser.parse_args()

    config = ZabbixLDAPConf(args.file)

    config.zbx_lowercase = args.lowercase
    config.zbx_deleteorphans = args.delete_orphans
    config.zbx_nocheckcertificate = args.no_check_certificate

    config.ldap_recursive = args.recursive
    config.ldap_wildcard_search = args.wildcard_search
    config.ldap_disabledmode = args.disabled_mode
    config.ldap_deletedmode = args.deleted_mode

    config.verbose = args.verbose
    config.dryrun = args.dryrun

    level = logging.DEBUG if config.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")

    ldap_conn = LDAPConn(config)

    zabbix_conn = ZabbixConn(config, ldap_conn)

    zabbix_conn.connect()

    zabbix_conn.sync_users()

if __name__ == '__main__':
    main()
