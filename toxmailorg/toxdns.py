#!/usr/bin/env python3
# Copyright (c) 2014 Zodiac Labs. All rights reserved.
import dnslib.server
import dnslib
import time
import binascii
import os
import sys
import json

import pwd
import grp

from toxmailorg import cryptocore

ch_A = ord("A")
ch_Z = ord("Z")
ch_a = ord("a")
ch_z = ord("z")
ch_ZERO = ord("0")
ch_FIVE = ord("5")

ir1 = lambda c: c <= ch_Z and c >= ch_A
ir2 = lambda c: c <= ch_z and c >= ch_a
ir3 = lambda c: c <= ch_FIVE and c >= ch_ZERO
BASE32_SRC = b"abcdefghijklmnopqrstuvwxyz012345"

# q: why not use python's base64 module?
# a: <+irungentoo> notsecure, I told you we should have used standard base32
#    <notsecure> Jfreegman, irungentoo wanted to use a-z,2-7 for base32,
#                I chose a-z,0-5
#    <notsecure> he said it would fuck with people using standard base32
#                functions
def notsecure32_decode(src):
    ret = []
    bits = 0
    op = 0
    for char in (ord(s) for s in src):
        if ir1(char):
            char -= ch_A
        elif ir2(char):
            char -= ch_a
        elif ir3(char):
            char = (char - ch_ZERO + 26)
        else:
            raise ValueError("this is an error apparently")

        op = (op | (char << bits)) % 256;
        bits += 5;

        if bits >= 8:
            bits -= 8
            ret.append(op)
            op = (char >> (5 - bits)) % 256;

    return bytes(ret)

# TODO optimize
def notsecure32_encode(src):
    sl = len(src)
    ret = []
    bits = 0
    i = 0
    while(i < sl):
        c1 = src[i]
        try:
            c2 = src[i + 1]
        except IndexError:
            c2 = 0
        a = BASE32_SRC[((c1 >> bits) | (c2 << (8 - bits))) & 0x1F]
        ret.append(a)
        bits += 5
        if bits >= 8:
            bits -= 8
            i += 1
    return bytes(ret)

class ToxResolver(dnslib.server.BaseResolver):
    def __init__(self, cryptocore, cfg):
        self.home = cfg["hostname"].encode("utf8")
        self.cryptocore = cryptocore
        self.ttl = cfg["dns_record_ttl"]
        with open("names.json", "r") as namelist_f:
            self.names = json.load(namelist_f)

        self.workable_domains = set(k.split("@")[1] for k in self.names)

    def resolve(self, request, handler):
        question = request.get_q()
        req_name = str(question.get_qname())
        # TXT = 16
        reply = request.reply()

        pivot = req_name.rfind("_tox.")
        if pivot == -1:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
            return reply

        name = req_name[:pivot].rstrip(".")
        suffix = req_name[pivot:]
        domain = suffix[5:].rstrip(".")

        if question.qtype == 16:
            if not name and domain in self.workable_domains:
                reply.add_answer(dnslib.RR(req_name, 16, ttl=0,
                    rdata=dnslib.TXT(self.cryptocore.public_key.encode("ascii"))))
                return reply

            first_try = self.try_tox3_resolve(reply, name, domain, req_name)
            if not first_try:
                return self.try_tox1_resolve(reply, name, domain, req_name)
            else:
                return first_try
        elif question.qtype == 2:
            reply.add_answer(dnslib.RR(req_name, 2, ttl=86400,
                                       rdata=dnslib.NS(self.home)
                                       ))
            return reply
        else:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
            return reply
        return reply

    def try_tox3_resolve(self, reply, name, domain, req_name):
        if not name.startswith("_"):
            return None

        encrypted = name.replace(".", "")[1:]
        try:
            b = notsecure32_decode(encrypted)
            nonce = b[:4] + (b"\0" * 20)
            ck = b[4:36]
            payload = b[36:]
            dec_name = self.cryptocore.dsrep_decode_name(ck, nonce, payload)
        except Exception:
            return None

        try:
            dec_name = dec_name.decode("utf8")
        except UnicodeDecodeError:
            return None

        toxid = self.names.get("{0}@{1}".format(dec_name, domain))
        if not toxid:
            return None

        msg = binascii.unhexlify(toxid)
        nonce_reply = b[:4] + b"\x01" + (b"\0" * 19)
        ct = self.cryptocore.dsrec_encrypt_key(ck, nonce_reply, msg)
        key_part = notsecure32_encode(ct).decode("ascii")

        base = "v=tox3;id={0}".format(key_part).encode("utf8")
        reply.add_answer(dnslib.RR(req_name, 16, ttl=0,
                         rdata=dnslib.TXT(base)))
        return reply

    def try_tox1_resolve(self, reply, name, domain, req_name):
        toxid = self.names.get("{0}@{1}".format(name, domain))
        if not toxid:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
            return reply
        else:
            rec = "v=tox1;id={0}".format(toxid).encode("utf8")
            reply.add_answer(dnslib.RR(req_name, 16, ttl=self.ttl,
                                       rdata=dnslib.TXT(rec)))
            return reply

def make_server(cryptocore, cfg):
    return dnslib.server.DNSServer(ToxResolver(cryptocore, cfg),
                                   port=cfg["dns_listen_port"],
                                   address=cfg["dns_listen_addr"],
                                   logger=None,
                                   tcp=False)

def main():
    with open("config.json", "r") as config_file:
        cfg = json.load(config_file)

    cc = cryptocore.CryptoCore()
    print("Hi.")
    print("My tox3 public key is {0}.".format(cc.public_key))

    if "pid_file" in cfg:
        with open(cfg["pid_file"], "w") as pid:
            pid.write(str(os.getpid()))

    try:
        server = make_server(cc, cfg)
        if "suid" in cfg:
            print("SUID...")
            if os.getuid() == 0:
                if ":" not in cfg["suid"]:
                    user = cfg["suid"]
                    group = None
                else:
                    user, group = cfg["suid"].split(":", 1)
                uid = pwd.getpwnam(user).pw_uid
                if group:
                    gid = grp.getgrnam(group).gr_gid
                else:
                    gid = pwd.getpwnam(user).pw_gid
                os.setgid(gid)
                os.setuid(uid)
            else:
                print("error: we're not root. Exiting.")
                sys.exit()
        server.start()
    finally:
        os.remove(cfg["pid_file"])

if __name__ == "__main__":
    main()

