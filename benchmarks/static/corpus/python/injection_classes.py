# SPDX-License-Identifier: Apache-2.0
# New injection CWE classes via the interprocedural taint engine: XXE (GF-430),
# unsafe reflection (GF-434), LDAP injection (GF-432). A literal/constant argument
# is not tainted and is not flagged.
from lxml import etree
import importlib


def parse_xml(request):
    data = request.get("xml")
    etree.fromstring(data)                       # EXPECT GF-430


def safe_xml():
    etree.fromstring("<root/>")                  # literal: not tainted


def load_class(request):
    name = request.get("cls")
    importlib.import_module(name)                 # EXPECT GF-434


def ldap_lookup(request, conn):
    uid = request.get("uid")
    conn.search_s("dc=example", 2, "(uid=" + uid + ")")  # EXPECT GF-432
