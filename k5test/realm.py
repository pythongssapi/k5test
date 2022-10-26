# Copyright (C) 2021 by Red Hat, Inc.
# Copyright (C) 2014 by Solly Ross
# Copyright (C) 2010 by the Massachusetts Institute of Technology.
# All rights reserved.

# Export of this software from the United States of America may
#   require a specific license from the United States Government.
#   It is the responsibility of any person or organization contemplating
#   export to obtain such a license before exporting.
#
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of M.I.T. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  Furthermore if you modify this software you must label
# your software as modified software and not distribute it in such a
# fashion that it might be confused with the original M.I.T. software.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.

# Changes from original:
#   - modified to work with Python's unittest
#   - added Heimdal support
#   - removed some Python 2 specific code
import abc
import copy
import logging
import os
import shlex
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile

from k5test import _utils

_LOG = logging.getLogger(__name__)


def _cfg_merge(cfg1, cfg2):
    if not cfg2:
        return cfg1
    if not cfg1:
        return cfg2
    result = copy.deepcopy(cfg1)
    for key, value2 in cfg2.items():
        if value2 is None or key not in result:
            result[key] = copy.deepcopy(value2)
        else:
            value1 = result[key]
            if isinstance(value1, dict):
                if not isinstance(value2, dict):
                    raise TypeError(
                        "value at key '{key}' not dict: "
                        "{type}".format(key=key, type=type(value2))
                    )
                result[key] = _cfg_merge(value1, value2)
            else:
                result[key] = copy.deepcopy(value2)
    return result


def _discover_path(name, default, paths):
    path = shutil.which(name)
    if path is not None:
        _LOG.debug(f"Using discovered path for {name} ({path})")
    else:
        path = paths.get(name, default)
        _LOG.debug(f"Using default path for {name} ({path}): {e}")
    return path


class K5Realm(metaclass=abc.ABCMeta):
    """An object representing a functional krb5 test realm."""

    def __new__(cls, *args, **kwargs):
        provider_cls = cls

        if provider_cls == K5Realm:
            krb5_config = _discover_path("krb5-config", "/usr/bin/krb5-config", kwargs)

            try:
                krb5_version = subprocess.check_output(
                    [krb5_config, "--version"], stderr=subprocess.STDOUT
                )
                krb5_version = krb5_version.decode(
                    sys.getfilesystemencoding() or sys.getdefaultencoding()
                )

                # macOS output doesn't contain Heimdal
                if "heimdal" in krb5_version.lower() or (
                    sys.platform == "darwin" and krb5_config == "/usr/bin/krb5-config"
                ):
                    provider_cls = HeimdalRealm
                else:
                    provider_cls = MITRealm

            except Exception as e:
                _LOG.debug(
                    f"Failed to determine gssapi provider, defaulting " f"to MIT: {e}"
                )
                provider_cls = MITRealm

        return super(K5Realm, cls).__new__(provider_cls)

    def __init__(
        self,
        realm="KRBTEST.COM",
        portbase=61000,
        krb5_conf=None,
        kdc_conf=None,
        create_kdb=True,
        krbtgt_keysalt=None,
        create_user=True,
        get_creds=True,
        create_host=True,
        start_kdc=True,
        start_kadmind=False,
        existing=None,
        **paths,
    ):

        if existing is not None:
            self.tmpdir = existing
            self.is_existing = True
        else:
            self.tmpdir = tempfile.mkdtemp(suffix="-krbtest")
            self.is_existing = False

        self.realm = realm
        self.portbase = portbase
        self.user_princ = "user@" + self.realm
        self.admin_princ = "user/admin@" + self.realm
        self.host_princ = "host/%s@%s" % (self.hostname, self.realm)
        self.nfs_princ = "nfs/%s@%s" % (self.hostname, self.realm)
        self.krbtgt_princ = "krbtgt/%s@%s" % (self.realm, self.realm)
        self.keytab = os.path.join(self.tmpdir, "keytab")
        self.client_keytab = os.path.join(self.tmpdir, "client_keytab")
        self.ccache = os.path.join(self.tmpdir, "ccache")
        self.kadmin_ccache = os.path.join(self.tmpdir, "kadmin_ccache")
        self._kdc_proc = None
        self._kadmind_proc = None
        krb5_conf_path = os.path.join(self.tmpdir, "krb5.conf")
        kdc_conf_path = os.path.join(self.tmpdir, "kdc.conf")
        self.env = self._make_env(krb5_conf_path, kdc_conf_path)

        self._daemons = []

        self._init_paths(**paths)

        if existing is None:
            self._create_conf(_cfg_merge(self._krb5_conf, krb5_conf), krb5_conf_path)
            if self._kdc_conf or kdc_conf:
                self._create_conf(_cfg_merge(self._kdc_conf, kdc_conf), kdc_conf_path)
            self._create_acl()
            self._create_dictfile()

            if create_kdb:
                self.create_kdb()
            if krbtgt_keysalt and create_kdb:
                self.change_password(self.krbtgt_princ, keysalt=krbtgt_keysalt)
            if create_user and create_kdb:
                self.addprinc(self.user_princ, self.password("user"))
                self.addprinc(self.admin_princ, self.password("admin"))
            if create_host and create_kdb:
                self.addprinc(self.host_princ)
                self.extract_keytab(self.host_princ, self.keytab)
            if start_kdc and create_kdb:
                self.start_kdc()
            if start_kadmind and create_kdb:
                self.start_kadmind()

        if get_creds and (
            (create_kdb and create_user and start_kdc) or self.is_existing
        ):
            self.kinit(self.user_princ, self.password("user"))
            self.klist()

    @abc.abstractproperty
    def provider(self):
        pass

    @abc.abstractproperty
    def _default_paths(self):
        pass

    @abc.abstractproperty
    def _krb5_conf(self):
        pass

    @abc.abstractproperty
    def _kdc_conf(self):
        pass

    @abc.abstractmethod
    def create_kdb(self):
        pass

    @abc.abstractmethod
    def addprinc(self, princname, password=None):
        pass

    @abc.abstractmethod
    def change_password(self, principal, password=None, keysalt=None):
        pass

    @abc.abstractmethod
    def extract_keytab(self, princname, keytab):
        pass

    @abc.abstractmethod
    def kinit(self, princname, password=None, flags=None, verbose=True, **keywords):
        pass

    @abc.abstractmethod
    def klist(self, ccache=None, **keywords):
        pass

    @abc.abstractclassmethod
    def klist_keytab(self, keytab=None, **keywords):
        pass

    @abc.abstractmethod
    def prep_kadmin(self, princname=None, pw=None, flags=None):
        pass

    @abc.abstractmethod
    def run_kadmin(self, query, **keywords):
        pass

    @abc.abstractmethod
    def run_kadminl(self, query, **keywords):
        pass

    @abc.abstractmethod
    def start_kdc(self, args=None, env=None):
        pass

    @abc.abstractmethod
    def start_kadmind(self, env=None):
        pass

    def _init_paths(self, **paths):
        for attr, name, default in self._default_paths:
            value = _discover_path(name, default, paths)
            setattr(self, attr, value)

    def _create_conf(self, profile, filename):
        with open(filename, "w") as conf_file:
            for section, contents in profile.items():
                conf_file.write("[%s]\n" % section)
                self._write_cfg_section(conf_file, contents, 1)

    def _write_cfg_section(self, conf_file, contents, indent_level):
        indent = "\t" * indent_level
        for name, value in contents.items():
            name = self._subst_cfg_value(name)
            if isinstance(value, dict):
                # A dictionary value yields a list subsection.
                conf_file.write("%s%s = {\n" % (indent, name))
                self._write_cfg_section(conf_file, value, indent_level + 1)
                conf_file.write("%s}\n" % indent)
            elif isinstance(value, list):
                # A list value yields multiple values for the same name.
                for item in value:
                    item = self._subst_cfg_value(item)
                    conf_file.write("%s%s = %s\n" % (indent, name, item))
            elif isinstance(value, str):
                # A string value yields a straightforward variable setting.
                value = self._subst_cfg_value(value)
                conf_file.write("%s%s = %s\n" % (indent, name, value))
            elif value is not None:
                raise TypeError(
                    "Unknown config type at key '{key}': "
                    "{type}".format(key=name, type=type(value))
                )

    @property
    def hostname(self):
        return "localhost" if sys.platform == "darwin" else socket.getfqdn()

    def _subst_cfg_value(self, value):
        template = string.Template(value)
        return template.substitute(
            realm=self.realm,
            tmpdir=self.tmpdir,
            hostname=self.hostname,
            port0=self.portbase,
            port1=self.portbase + 1,
            port2=self.portbase + 2,
            port3=self.portbase + 3,
            port4=self.portbase + 4,
            port5=self.portbase + 5,
            port6=self.portbase + 6,
            port7=self.portbase + 7,
            port8=self.portbase + 8,
            port9=self.portbase + 9,
        )

    def _create_acl(self):
        filename = os.path.join(self.tmpdir, "acl")
        with open(filename, "w") as acl_file:
            acl_file.write("%s *\n" % self.admin_princ)
            acl_file.write("kiprop/%s@%s p\n" % (self.hostname, self.realm))

    def _create_dictfile(self):
        filename = os.path.join(self.tmpdir, "dictfile")
        with open(filename, "w") as dict_file:
            dict_file.write("weak_password\n")

    def _make_env(self, krb5_conf_path, kdc_conf_path):
        env = {}
        env["KRB5_CONFIG"] = krb5_conf_path
        env["KRB5_KDC_PROFILE"] = kdc_conf_path or os.devnull
        env["KRB5CCNAME"] = self.ccache
        env["KRB5_KTNAME"] = self.keytab
        env["KRB5_CLIENT_KTNAME"] = self.client_keytab
        env["KRB5RCACHEDIR"] = self.tmpdir
        env["KPROPD_PORT"] = str(self.kprop_port())
        env["KPROP_PORT"] = str(self.kprop_port())
        return env

    def run(self, args, env=None, input=None, expected_code=0):
        if env is None:
            env = self.env

        if input:
            infile = subprocess.PIPE
        else:
            infile = subprocess.DEVNULL

        proc = subprocess.Popen(
            args,
            stdin=infile,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
        if input:
            inbytes = input.encode()
        else:
            inbytes = None
        (outdata, blank_errdata) = proc.communicate(inbytes)
        code = proc.returncode
        cmd = " ".join(args)
        outstr = outdata.decode()
        _LOG.debug("[OUTPUT FROM `{args}`]\n{output}\n".format(args=cmd, output=outstr))
        if code != expected_code:
            raise Exception(
                "Unexpected return code "
                "for command `{args}`: {code}".format(args=cmd, code=code)
            )

        return outdata

    def __del__(self):
        pass

    def kprop_port(self):
        return self.portbase + 3

    def server_port(self):
        return self.portbase + 5

    def _start_daemon(self, args, env=None, sentinel=None):
        if env is None:
            env = self.env

        stdout = subprocess.PIPE if sentinel else subprocess.DEVNULL
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            env=env,
        )
        cmd = " ".join(args)
        while sentinel:
            line = proc.stdout.readline().decode()
            if line == "":
                code = proc.wait()
                raise Exception(
                    "`{args}` failed to start "
                    "with code {code}".format(args=cmd, code=code)
                )
            else:
                _LOG.debug(
                    "[OUTPUT FROM `{args}`]\n"
                    "{output}\n".format(args=cmd, output=line)
                )

            if sentinel in line:
                break

        self._daemons.append(proc)

        return proc

    def _stop_daemon(self, proc):
        proc.terminate()
        proc.communicate()
        self._daemons.remove(proc)

    def stop_kdc(self):
        assert self._kdc_proc is not None
        self._stop_daemon(self._kdc_proc)
        self._kdc_proc = None

    def stop_kadmind(self):
        assert self._kadmind_proc is not None
        self._stop_daemon(self._kadmind_proc)
        self._kadmind_proc = None

    def stop(self):
        if self._kdc_proc:
            self.stop_kdc()
        if self._kadmind_proc:
            self.stop_kadmind()

        if self.tmpdir and not self.is_existing:
            shutil.rmtree(self.tmpdir)

    def password(self, name):
        """Get a weakly random password from name, consistent across calls."""
        return name + str(os.path.basename(self.tmpdir))

    def special_env(self, name, has_kdc_conf, krb5_conf=None, kdc_conf=None):
        krb5_conf_path = os.path.join(self.tmpdir, f"krb5.conf.{name}")
        krb5_conf = _cfg_merge(self._krb5_conf, krb5_conf)
        self._create_conf(krb5_conf, krb5_conf_path)
        if has_kdc_conf and self._kdc_conf:
            kdc_conf_path = os.path.join(self.tmpdir, f"kdc.conf.{name}")
            kdc_conf = _cfg_merge(self._kdc_conf, kdc_conf)
            self._create_conf(kdc_conf, kdc_conf_path)
        else:
            kdc_conf_path = None
        return self._make_env(krb5_conf_path, kdc_conf_path)

    def kill_daemons(self):
        # clean up daemons
        for proc in self._daemons:
            os.kill(proc.pid, signal.SIGTERM)


class MITRealm(K5Realm):
    @property
    def provider(self):
        return "mit"

    @property
    def _default_paths(self):
        return [
            ("kdb5_util", "kdb5_util", "/usr/sbin/kdb5_util"),
            ("krb5kdc", "krb5kdc", "/usr/sbin/krb5kdc"),
            ("kadmin", "kadmin", "/usr/bin/kadmin"),
            ("kadmin_local", "kadmin.local", "/usr/sbin/kadmin.local"),
            ("kadmind", "kadmind", "/usr/sbin/kadmind"),
            ("kprop", "kprop", "/usr/sbin/kprop"),
            ("_kinit", "kinit", "/usr/bin/kinit"),
            ("_klist", "klist", "/usr/bin/klist"),
        ]

    @property
    def _krb5_conf(self):
        return {
            "libdefaults": {"default_realm": "$realm", "dns_lookup_kdc": "false"},
            "realms": {
                "$realm": {
                    "kdc": "$hostname:$port0",
                    "admin_server": "$hostname:$port1",
                    "kpasswd_server": "$hostname:$port2",
                }
            },
        }

    @property
    def _kdc_conf(self):
        plugin_dir = _utils.find_plugin_dir()
        db_module_dir = None
        if plugin_dir:
            db_module_dir = os.path.join(plugin_dir, "kdc")

        return {
            "realms": {
                "$realm": {
                    "database_module": "db",
                    "iprop_port": "$port4",
                    "key_stash_file": "$tmpdir/stash",
                    "acl_file": "$tmpdir/acl",
                    "dict_file": "$tmpdir/dictfile",
                    "kadmind_port": "$port1",
                    "kpasswd_port": "$port2",
                    "kdc_ports": "$port0",
                    "kdc_tcp_ports": "$port0",
                    "database_name": "$tmpdir/db",
                }
            },
            "dbmodules": {
                "db_module_dir": db_module_dir,
                "db": {"db_library": "db2", "database_name": "$tmpdir/db"},
            },
            "logging": {
                "admin_server": "FILE:$tmpdir/kadmind5.log",
                "kdc": "FILE:$tmpdir/kdc.log",
                "default": "FILE:$tmpdir/others.log",
            },
        }

    def create_kdb(self):
        self.run([self.kdb5_util, "create", "-W", "-s", "-P", "master"])

    def addprinc(self, princname, password=None):
        args = ["addprinc"]
        if password:
            args.extend(["-pw", password])
        else:
            args.append("-randkey")

        args.append(princname)
        self.run_kadminl(args)

    def change_password(self, principal, password=None, keysalt=None):
        args = ["cpw"]

        if password:
            args.extend(["-pw", password])
        else:
            args.append("-randkey")

        if keysalt:
            args.extend("-e", keysalt)

        args.append(principal)
        self.run_kadminl(args)

    def extract_keytab(self, princname, keytab):
        self.run_kadminl(f"ktadd -k {keytab} -norandkey {princname}")

    def kinit(self, princname, password=None, flags=None, verbose=True, **keywords):
        cmd = [self._kinit]
        if verbose:
            cmd.append("-V")
        if flags:
            cmd.extend(flags)
        cmd.append(princname)

        input = password + "\n" if password else None
        return self.run(cmd, input=input, **keywords)

    def klist(self, ccache=None, **keywords):
        return self.run([self._klist, ccache or self.ccache], **keywords)

    def klist_keytab(self, keytab=None, **keywords):
        return self.run([self._klist, "-k", keytab or self.keytab], **keywords)

    def prep_kadmin(self, princname=None, pw=None, flags=None):
        if princname is None:
            princname = self.admin_princ
            pw = self.password("admin")
        return self.kinit(
            princname,
            pw,
            flags=["-S", "kadmin/admin", "-c", self.kadmin_ccache] + (flags or []),
        )

    def run_kadmin(self, query, **keywords):
        return self.run(
            [self.kadmin, "-c", self.kadmin_ccache, "-q", query], **keywords
        )

    def run_kadminl(self, query, **keywords):
        if isinstance(query, list):
            query = " ".join([shlex.quote(q) for q in query])

        return self.run([self.kadmin_local, "-q", query], **keywords)

    def start_kdc(self, args=None, env=None):
        if self._kdc_proc:
            raise Exception("KDC has already started")

        start_args = [self.krb5kdc, "-n"]
        if args:
            start_args.extend(args)
        self._kdc_proc = self._start_daemon(start_args, env, "starting...")

    def start_kadmind(self, env):
        if self._kadmind_proc:
            raise Exception("kadmind has already started")

        dump_path = os.path.join(self.tmpdir, "dump")
        self._kadmind_proc = self._start_daemon(
            [
                self.kadmind,
                "-nofork",
                "-W",
                "-p",
                self.kdb5_util,
                "-K",
                self.kprop,
                "-F",
                dump_path,
            ],
            env,
            "starting...",
        )


class HeimdalRealm(K5Realm):
    @property
    def provider(self):
        return "heimdal"

    @property
    def _default_paths(self):
        base = "/System/Library/PrivateFrameworks/Heimdal.framework/Helpers"
        if sys.platform != "darwin":
            base = "/usr/libexec"

        return [
            ("krb5kdc", "kdc", os.path.join(base, "kdc")),
            ("kadmin", "kadmin", "/usr/bin/kadmin"),
            ("kadmin_local", "kadmin", "/usr/bin/kadmin"),
            ("kadmind", "kadmind", os.path.join(base, "kadmind")),
            ("_kinit", "kinit", "/usr/bin/kinit"),
            ("_klist", "klist", "/usr/bin/klist"),
            ("_ktutil", "ktutil", "/usr/bin/ktutil"),
        ]

    @property
    def _krb5_conf(self):
        return {
            "libdefaults": {
                "default_realm": "$realm",
                "default_keytab_name": "FILE:$tmpdir/keytab",
                "dns_lookup_kdc": "false",
                "dns_lookup_realm": "false",
            },
            "realms": {
                "$realm": {
                    "kdc": "$hostname:$port0",
                    "admin_server": "$hostname:$port1",
                    "kpasswd_server": "$hostname:$port2",
                }
            },
            "logging": {
                "kadmind": "FILE:$tmpdir/kadmind.log",
                "kdc": "FILE:$tmpdir/kdc.log",
                "kpasswdd": "FILE:$tmpdir/kpasswdd.log",
                "krb5": "FILE:$tmpdir/krb5.log",
                "default": "FILE:$tmpdir/others.log",
            },
            "kdc": {
                "database": {
                    "dbname": "$tmpdir/db",
                    "mkey_file": "$tmpdir/stash",
                    "acl_file": "$tmpdir/acl",
                    "log_file": "$tmpdir/db.log",
                },
                "ports": "$port0",
            },
        }

    @property
    def _kdc_conf(self):
        return

    def create_kdb(self):
        self.run_kadminl(
            ["stash", f"--key-file={self.tmpdir}/stash" "--random-password"]
        )
        self.run_kadminl(["init", self.realm], input="\n\n")

    def addprinc(self, princname, password=None):
        args = ["add", "--use-defaults"]
        if password:
            args.append(f"--password={password}")
        else:
            args.append("--random-key")

        args.append(princname)

        self.run_kadminl(args)

    def change_password(self, principal, password=None, keysalt=None):
        args = ["change_password"]

        if password:
            args.append(f"--password={password}")
        else:
            args.append("--random-key")

        if keysalt:
            args.extend("-e", keysalt)

        args.append(principal)
        self.run_kadminl(args)

    def extract_keytab(self, princname, keytab):
        self.run_kadminl(["ext", f"--keytab={keytab}", princname])

    def kinit(self, princname, password=None, flags=None, verbose=True, **keywords):
        cmd = [self._kinit]

        input = None
        if password:
            input = password + "\n"
            cmd.append("--password-file=STDIN")

        if flags:
            cmd.extend(flags)
        cmd.append(princname)

        return self.run(cmd, input=input, **keywords)

    def klist(self, ccache=None, **keywords):
        return self.run([self._klist, "-c", ccache or self.ccache], **keywords)

    def klist_keytab(self, keytab=None, **keywords):
        return self.run([self._ktutil, "-k", keytab or self.keytab, "list"], **keywords)

    def prep_kadmin(self, princname=None, pw=None, flags=None):
        raise NotImplementedError()  # Not needed right now

    def run_kadmin(self, query, **keywords):
        raise NotImplementedError()  # Not needed right now

    def run_kadminl(self, query, **keywords):
        if not isinstance(query, list):
            query = [query]

        args = [self.kadmin_local, "--local"]
        krb5_config = self.env.get("KRB5_CONFIG", None)
        if krb5_config:
            args.append(f"--config-file={krb5_config}")

        return self.run(args + query, **keywords)

    def start_kdc(self, args=None, env=None):
        if self._kdc_proc:
            raise Exception("KDC has already started")

        start_args = [self.krb5kdc]

        if sys.platform == "darwin":
            start_args.append("--no-sandbox")

        krb5_config = self.env.get("KRB5_CONFIG", None)
        if krb5_config:
            start_args.append("--config-file=%s" % krb5_config)

        if args:
            start_args.extend(args)

        # The KDC won't display the output to stdout, so there's no sentinel
        # to check.  Instead, read the log file for it.
        kdc_log = os.path.join(self.tmpdir, "kdc.log")
        with open(kdc_log, mode="w+") as log_fd:
            self._kdc_proc = self._start_daemon(start_args, env)

            while True:
                line = log_fd.readline()
                if "KDC started" in line:
                    break

    def start_kadmind(self, env=None):
        if self._kadmind_proc:
            raise Exception("kadmind has already started")

        config_file = f"--config-file={self._krb5_conf}"
        port = "--ports=%s" % (self.portbase + 1)
        args = [self.kadmind, config_file, port]
        self._kadmind_proc = self._start_daemon(args)
