#!/usr/bin/env python2

from __future__ import print_function

import os
import os.path
import sys
import yaml
import Milter
import logging
import logging.handlers
import re
import argparse
from email.header import decode_header

_FILE_VER = "to_be_filled_by_CI"


class ThisMilter(Milter.Base):

    def __init__(self, log, cfgobj=None, prod_mode=False):
        self.log = log
        self.cfgobj = cfgobj
        self.prod_mode = prod_mode
        self.MODETXT = " (dry run)" if not prod_mode else ""
        # Empty default subject seems correct for cases when subject is empty or omitted.
        # And I can't imagine a situation when this may be wrong.
        self.headers = {"subject": u""}
        self.actions = {"replace_recipient": self.action_replace_recipient}
        self.commits = [self.commit_T]

    def action_replace_recipient(self, sctx, actx):
        """
        Replaces recipient's address in the message
        :param sctx: step context
        :param actx: action context
        :return: nothing
        """
        data = {
            "env_sender": str(sctx["env_sender"]) if "env_sender" in sctx and sctx["env_sender"] is not None else None,
            "env_recipient": str(sctx["env_recipient"]) if "env_recipient" in sctx and sctx["env_recipient"] is not None else None,
            "subject": unicode(sctx["subject"]) if "subject" in sctx and sctx["subject"] is not None else None,
            "env_replacement": str(actx) if actx is not None else None
        }
        if data["env_sender"] is not None and data["env_sender"].isspace():
            data["env_sender"] = None
        if data["env_recipient"] is None or data["env_recipient"].isspace():
            raise RuntimeError("No recipient's address given or the address is invalid")
        if data["env_replacement"] is None or data["env_replacement"].isspace():
            raise RuntimeError("No replacing address given or the address is invalid")
        env_addr_start = "<"
        env_addr_end = ">"
        if data["env_replacement"].startswith(env_addr_start):
            env_addr_start = ""
        if data["env_replacement"].endswith(env_addr_end):
            env_addr_end = ""
        data["env_replacement"] = "{}{}{}".format(env_addr_start, data["env_replacement"], env_addr_end)
        if data["env_sender"] is not None:
            self.log.info("{}: search{}: in sender address {} for pattern {}".format(self.ID,
                                                                                     self.MODETXT,
                                                                                     self.F, data["env_sender"]))
        else:
            self.log.info("{}: search{}: accept any sender address".format(self.ID, self.MODETXT))
        if data["subject"] is not None:
            self.log.info("{}: search{}: in subject {} for pattern {}".
                           format(self.ID, self.MODETXT, self.headers["subject"].encode("unicode_escape"),
                                  data["subject"].encode("unicode_escape")))
        else:
            self.log.info("{}: search{}: accept any subject".format(self.ID, self.MODETXT))
        if (data["env_sender"] is None or re.search(data["env_sender"], self.F, re.I)) and \
                (data["subject"] is None or re.search(data["subject"], self.headers["subject"], re.I | re.UNICODE)):
            re_rcpt = re.compile(data["env_recipient"], re.I)
            changed = list(self.T["changed"])
            i = 0
            for addr in changed:
                self.log.info("{}: search{}: in recipient address {} for pattern {}".
                              format(self.ID, self.MODETXT, addr, data["env_recipient"]))
                if re_rcpt.search(addr):
                    self.log.warning("{}: replace{}: recipient {} with {}".format(self.ID, self.MODETXT, addr, data["env_replacement"]))
                    changed[i] = data["env_replacement"]
                i += 1
            self.T["changed"] = set(changed)
            self.log.debug("{}: recipients{}: {}".format(self.ID, self.MODETXT, self.T["changed"]))

    def commit_T(self):
        for addr in self.T["original"] - self.T["changed"]:
            self.log.info("{}: commit{}: delete recipient {}".format(self.ID, self.MODETXT, addr))
            if self.prod_mode:
                self.delrcpt(addr)
        for addr in self.T["changed"] - self.T["original"]:
            self.log.info("{}: commit{}: add recipient {}".format(self.ID, self.MODETXT, addr))
            if self.prod_mode:
                self.addrcpt(addr)

    def do_actions(self):
        if self.cfgobj is not None:
            for step in self.cfgobj:
                sctx = {}
                actions = {}
                for pkey, pval in step.iteritems():
                    if pkey == "actions":
                        actions = pval
                    else:
                        sctx[pkey] = pval
                for action in actions:
                    for akey, aval in action.iteritems():
                        self.actions[akey](sctx, aval)

    def do_commits(self):
        for commit in self.commits:
            commit()

    @Milter.noreply
    def envfrom(self, addr, *str):
        self.F = addr
        self.T = {}
        self.T["original"] = set()  # Original To-set
        self.T["changed"] = set()   # Changed To-set
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, addr, *str):
        self.T["original"].add(addr)
        self.T["changed"].add(addr)
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, field, value):
        decoded = decode_header(value)[0]
        self.headers[field.lower()] = unicode(decoded[0], decoded[1] or "ascii", "replace")
        return Milter.CONTINUE

    def eom(self):
        self.ID = self.getsymval('i')
        self.log.warning("{}: receive{}: from {} to {} with subject {}".
                         format(self.ID, self.MODETXT, self.F, ",".join(a for a in self.T["changed"]),
                                self.headers["subject"].encode("unicode_escape")))
        self.log.debug(u"{}: headers{}: {}".format(self.ID, self.MODETXT, self.headers))
        self.log.debug("{}: recipients{}: {}".format(self.ID, self.MODETXT, self.T["changed"]))
        try:
            self.do_actions()
        except Exception:
            self.log.exception("{}: Error in do_actions".format(self.ID))
        try:
            self.do_commits()
        except Exception:
            self.log.exception("{}: Error in do_commits".format(self.ID))
        return Milter.ACCEPT


def mfactory(log, cfgobj=None, prod_mode=False):
    class ThisMilterCustom(ThisMilter):
        def __init__(self):
            ThisMilter.__init__(self, log=log, cfgobj=cfgobj, prod_mode=prod_mode)
    return ThisMilterCustom


if __name__ == "__main__":
    prog_name = os.path.basename(sys.argv[0]).rsplit(".", 1)[0]
    prog_pid = os.getpid()
    defaults = {
        "syslog_address": "/dev/log",
        "socket_path": "/var/spool/postfix/private/{}".format(".".join((prog_name, "sock"))),
        "cfg_path": os.path.abspath(".".join((os.path.basename(sys.argv[0]).split(".")[0], "yml"))),
        "timeout": 60,
        "severity": "WARNING"
    }
    cmd = argparse.ArgumentParser(description="Milter that mangles envelope addresses")
    cmd.add_argument("-s", metavar="Path", help="Path to the socket to listen on ({})".format(defaults["socket_path"]),
                     default=defaults["socket_path"])
    cmd.add_argument("-l", metavar="Address or Path", help="Address of the syslog socket ({})".format(defaults["syslog_address"]),
                     default=defaults["syslog_address"])
    cmd.add_argument("-ll", metavar="Level", help="Logging severity level ({})".format(defaults["severity"]),
                     default=defaults["severity"])
    cmd.add_argument("-c", metavar="Path", help="Path to the YAML-formatted configuration file ({})".format(defaults["cfg_path"]),
                     default=defaults["cfg_path"])
    cmd.add_argument("-t", metavar="Num", help="Milter timeout, sec ({})".format(defaults["timeout"]), default=defaults["timeout"])
    cmd.add_argument("-p", help="Production mode (the milter by default runs in dry run mode and doesn't make any changes)",
                     action="store_true", default=False)
    cmd.add_argument("-version", action="version", version=_FILE_VER)
    cmdargs = cmd.parse_args()
    cfgobj = yaml.load(open(cmdargs.c))
    log_handler = logging.handlers.SysLogHandler(address=cmdargs.l,
                                                 facility=logging.handlers.SysLogHandler.LOG_MAIL)
    log_formatter = logging.Formatter(fmt="%(prog_name)s[%(prog_pid)d]: %%(message)s" % {"prog_name": prog_name,
                                                                                         "prog_pid": prog_pid})
    log_handler.setFormatter(log_formatter)
    log_logger = logging.getLogger(prog_name)
    log_logger.addHandler(log_handler)
    log_logger.setLevel(getattr(logging, cmdargs.ll.upper()))
    timeout = 60
    Milter.set_flags(Milter.ADDRCPT | Milter.DELRCPT)
    Milter.factory = mfactory(log_logger, cfgobj, cmdargs.p)
    Milter.runmilter(prog_name, cmdargs.s, cmdargs.t)
