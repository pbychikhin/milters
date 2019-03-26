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
        self.headers = {"subject": u"",
                        "from": u""}
        self.actions = {"replace_recipient": self.action_replace_recipient,
                        "add_recipient": self.action_add_recipient,
                        "del_recipient": self.action_del_recipient}
        self.commits = [self.commit_T]

    def __search(self, data, mode_and=True):
        """
        Searching phase. Used in actions below
        :param data: [{"name": "a descriptive name", "data": a list or tuple of "some text", "pattern": "a pattern to search for"}, ...]
        :param mode_and: True if all fields should match
        :return: True or False
        """
        for item in data:
            if item["data"] is not None and item["pattern"] is not None:
                if not isinstance(item["data"], (list, tuple)):
                    data_data = (item["data"], )
                else:
                    data_data = tuple(item["data"])
                for item_dd in data_data:
                    self.log.info("{}: search{}: in {} {} for pattern {}".format(
                        self.ID,
                        self.MODETXT,
                        item["name"],
                        item_dd.encode("unicode_escape") if item["is_unicode"] else item_dd,
                        item["pattern"].encode("unicode_escape") if item["is_unicode"] else item["pattern"]
                    ))
                    if item_dd is not None and re.search(item["pattern"], item_dd, re.I | re.UNICODE if item["is_unicode"] else re.I):
                        if not mode_and:
                            return True
                        pass
                    else:
                        return False
            elif item["pattern"] is None:
                self.log.info("{}: search{}: accept any {}".format(self.ID, self.MODETXT, item["name"]))
            else:
                return False
        return True

    @staticmethod
    def __normalize_address(address):
        """
        Returns an email address enclosed in < and > brackets
        :param address:
        :return: normalized address
        """
        env_addr_start = "<"
        env_addr_end = ">"
        if address.startswith(env_addr_start):
            env_addr_start = ""
        if address.endswith(env_addr_end):
            env_addr_end = ""
        return "{}{}{}".format(env_addr_start, address, env_addr_end)

    @staticmethod
    def __str_or_none(var, str_func=str):
        """
        Ensure var is non-empty string
        :param var: supposedly, a string
        :param str_func: a function which returns string. Can be re-defined to return, for instance, unicode
        :return: var as a str or None if var is None or empty str
        """
        str_var = str_func(var)
        if var is None or len(str_var) == 0 or str_var.isspace():
            return None
        return str_var

    def __prepare_action(self, actx, actx_desc, map_func=None, map_func_args=None):
        """
        Processes action context and returns a list of strings or mapping function return values
        :param actx: actions context - a string or a list of strings. If an item is not a string, it will be casted to string
        :param actx_desc: action context description. Used in log messages
        :param map_func: optional function to be mapped to an items in actx
        :param map_func_args: list of map_func arguments. Firs argument is an item from actx
        :return: a list of strings or mapping function return values
        """
        def basic_map_func(*arg):
            return arg[0]
        map_func = basic_map_func if map_func is None else map_func
        map_func_args = [] if map_func_args is None else map_func_args
        if not isinstance(actx, (list, tuple)):
            str_actx = self.__str_or_none(actx)
            if str_actx is None:
                raise RuntimeError("{} is not given or invalid".format(actx_desc))
            rv = [map_func(*[str_actx] + map_func_args)]
        else:
            rv = []
            for item in actx:
                str_item = self.__str_or_none(item)
                if str_item is None:
                    raise RuntimeError("{} is not given or invalid".format(actx_desc))
                rv.append(map_func(*[str_item] + map_func_args))
        return rv

    def action_del_recipient(self, sctx, actx):
        """
        Deletes recipient's address in the message
        :param sctx: step context
        :param actx: action context
        :return: nothing
        """
        search_clauses = [
            {
                "name": "Envelope Sender",
                "data": self.F,
                "pattern": self.__str_or_none(sctx.get("env_sender"))
            },
            {
                "name": "Envelope Recipient",
                "data": self.T["changed"],
                "pattern": self.__str_or_none(sctx.get("env_recipient"))
            }
        ]
        for name in self.headers.keys():
            name_lower = name.lower()
            search_clauses.append(
                {
                    "name": name,
                    "data": self.headers.get(name_lower),
                    "pattern": self.__str_or_none(sctx.get(name_lower), unicode)
                }
            )
        if self.__search(search_clauses):
            env_deletion = self.__prepare_action(actx, "address for deletion", re.compile, [re.I])
            changed = set(self.T["changed"])
            for titem in self.T["changed"]:
                for ditem in env_deletion:
                    if ditem.search(titem):
                        self.log.warning("{}: del{}: recipient {}".format(self.ID, self.MODETXT, titem))
                        changed.remove(titem)
                        break
            self.step_changes.append((self.T["changed"].intersection_update, changed))
            self.log.debug("{}: recipients{}: {}".format(self.ID, self.MODETXT, changed))

    def action_replace_recipient(self, sctx, actx):
        """
        Replaces recipient's address in the message
        :param sctx: step context
        :param actx: action context
        :return: nothing
        """
        env_recipient = str(sctx["env_recipient"]) if "env_recipient" in sctx and sctx["env_recipient"] is not None \
                                                      and not str(sctx["env_recipient"]).isspace() else None
        if not isinstance(actx, list):
            str_actx = str(actx)
            if actx is None or str_actx.isspace():
                raise RuntimeError("No address for deletion given or the address is invalid")
            env_replacement = [re.compile(str_actx, re.I)]
        else:
            env_replacement = []
            for item in actx:
                str_item = str(item)
                if item is None or str_item.isspace():
                    raise RuntimeError("No address for deletion given or the address is invalid")
                env_replacement.append(re.compile(str_item, re.I))
        for k, v in [{env_recipient, "recipient's"}, {env_replacement, "replacing"}]:
            if k is None:
                raise RuntimeError("No {} address given or the address is invalid".format(v))
        search_clauses = [
            {
                "name": "Envelope Sender",
                "data": self.F,
                "pattern": str(sctx["env_sender"]) if "env_sender" in sctx \
                    and sctx["env_sender"] is not None and not str(sctx["env_sender"]).isspace() else None
            },
            {
                "name": "Envelope Recipient",
                "data": self.T["changed"],
                "pattern": env_recipient
            }
        ]
        for name in ("Subject", "From"):
            name_lower = name.lower()
            search_clauses.append(
                {
                    "name": name,
                    "data": self.headers[name_lower] if name_lower in self.headers and self.headers[name_lower] is not None else None,
                    "pattern": unicode(sctx[name_lower]) if name_lower in sctx and sctx[name_lower] is not None else None
                }
            )
        if self.__search(search_clauses):
            env_replacement = self.__normalize_address(env_replacement)

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
            changed = set(changed)
            self.step_changes.append((self.T["changed"].difference_update, self.T["changed"] - changed))  # First, we're removing the elements that's been replaced
            self.step_changes.append((self.T["changed"].update, changed - self.T["changed"]))             # Second, we're adding the replacing elements
            self.log.debug("{}: recipients{}: {}".format(self.ID, self.MODETXT, changed))

    def action_add_recipient(self, sctx, actx):
        """
        Adds recipient's address to the message
        :param sctx: step context
        :param actx: action context
        :return: nothing
        """
        data = {
            "env_sender": str(sctx["env_sender"]) if "env_sender" in sctx and sctx["env_sender"] is not None else None,
            "env_recipient": str(sctx["env_recipient"]) if "env_recipient" in sctx and sctx["env_recipient"] is not None else None,
            "subject": unicode(sctx["subject"]) if "subject" in sctx and sctx["subject"] is not None else None,
        }
        if data["env_sender"] is not None and data["env_sender"].isspace():
            data["env_sender"] = None
        if data["env_recipient"] is not None and data["env_recipient"].isspace():
            data["env_recipient"] = None
        if not isinstance(actx, list):
            data["env_addition"] = [str(actx) if actx is not None else None]
        else:
            data["env_addition"] = []
            for item in actx:
                data["env_addition"].append(item if item is not None else None)
        index = 0
        for item in data["env_addition"]:
            if item is None or item.isspace():
                raise RuntimeError("No address for addition given or the address is invalid")
            env_addr_start = "<"
            env_addr_end = ">"
            if item.startswith(env_addr_start):
                env_addr_start = ""
            if item.endswith(env_addr_end):
                env_addr_end = ""
            data["env_addition"][index] = "{}{}{}".format(env_addr_start, item, env_addr_end)
            index += 1
        data["env_addition"] = set(data["env_addition"])
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
            found = False
            changed = set(self.T["changed"])
            if data["env_recipient"] is None:
                self.log.info("{}: search{}: accept any recipient address".format(self.ID, self.MODETXT))
                found = True
            else:
                re_rcpt = re.compile(data["env_recipient"], re.I)
                for addr in changed:
                    self.log.info("{}: search{}: in recipient address {} for pattern {}".
                                  format(self.ID, self.MODETXT, addr, data["env_recipient"]))
                    if re_rcpt.search(addr):
                        found = True
                        break
            if found:
                self.log.warning("{}: add{}: recipient {}".format(self.ID, self.MODETXT,
                                                                  ",".join(a for a in data["env_addition"])))
                changed |= data["env_addition"]
                self.step_changes.append((self.T["changed"].update, changed - self.T["changed"]))
                self.log.debug("{}: recipients{}: {}".format(self.ID, self.MODETXT, changed))

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
                self.step_changes = []  # Each action should add a 2-element tuple to this list.
                                        # The firs element is a method that merges the changes which are made by the action.
                                        # The second element is the data to be processed by the first element.
                for action in actions:
                    for akey, aval in action.iteritems():
                        self.actions[akey](sctx, aval)
                for change in self.step_changes:
                    self.log.debug("{}: merge{}: {} for {}".format(self.ID, self.MODETXT, change[0], change[1]))
                    change[0](change[1])
                    self.log.debug("{}: merge{}: updated object is now {}".format(self.ID, self.MODETXT, change[0].__self__))

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
    Milter.set_flags(Milter.ADDRCPT | Milter.DELRCPT)
    Milter.factory = mfactory(log_logger, cfgobj, cmdargs.p)
    Milter.runmilter(prog_name, cmdargs.s, cmdargs.t)
