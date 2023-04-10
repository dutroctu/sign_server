#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# An example of a standalone application using the internal API of Gunicorn.
#
#   $ python standalone_app.py
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import multiprocessing

import gunicorn.app.base


CERT_ENV="CERT"
CERT_KEY_ENV="CERT_KEY"
DATABASE_ENV="DATABASE"
STORAGE_ENV="STORAGE"
DBUSER_ENV="DBUSER"
DBPASS_ENV="DBPASS"

# WARNING: Beware when setting multi workers, as they're running in differe processes, data may not share, like login session
# TODO: handle sharing memory among processes. i.e. using memcache?
def number_of_workers():
    # return (multiprocessing.cpu_count() * 2) + 1
    return 1
    # return multiprocessing.cpu_count()

def number_of_thread():
    return (multiprocessing.cpu_count() * 2) + 1


class StandaloneApplication(gunicorn.app.base.BaseApplication):

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        common.log("load_config")
        config = {key: value for key, value in self.options.items()
                  if key in self.cfg.settings and value is not None}
        
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        common.log("Load app")
        return self.application



import getopt
import sys
import os
import traceback
PARAM_SHORT_ARG="hb:c:w:"
PARAM_LONG_ARG = {
    "help":"Print Help", 
    "bind=": "Server address, in format <ip>:<port>",
    "guniconfig=":"path of gunicorn config file",
    "worker=": "The number of workers",
    "dbkey=": "database password (variable env.) ",
    "filekey=": "storage password (variable env.) ",
    "cert=": "path to server cert file (variable env.) , for HTTPS",
    "key=": "path to server key (variable env.) , for HTTPS",
    "output=": "path to working dir of server",
    "config=": "path to config file of server, load when init, if not sepecified, defaul value will be used and config.json will be generated",
    "thread=": "the numer of thread", 
    "dbname=": "name of db to be used, if not set, default is 'signing'",
    "dbuser=": "username (variable env.) to login db'",
    "dbpass=": "password (variable env.) to login db",
    "log=": "path to runtime log",
    }

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def printHelp():
    print ("\nCommand:")
    # print("\t%s -h|--help -d|--config <config file path> -d|--dbkey <pwd to encrypt database> -f|--filekey <pwd to encrypt file>" % os.path.basename(sys.argv[0]))
    print("\t%s --<option name> <value>", os.path.basename(sys.argv[0]))
    print("\tOptions")
    for item, value in PARAM_LONG_ARG.items():
        key = item if item.find("=") < 0 else item[:item.find("=")]
        print("--%s \t: %s\n" %(key , value))
    print ("\n")

if __name__ == '__main__':
    # print("Hello from server")
    from server import app
    from server.app import DEBUG
    from server import common as common
    from server import applog as applog
    from server.applog import logD
    # bind='%s:%s' % (common.get_ip(), app.get_ip())
    bind=None
    ip=None
    port=None
    guniconfig=""
    appconfigpath=None
    worker=number_of_workers()
    thread=number_of_thread()
    dbkey=None
    filekey=None
    dbkey_env=None
    filekey_env=None
    cert_path=None
    cert_key_path=None
    cert_env=None
    cert_key_env=None
    workingdir=ROOT_DIR
    timeout=2*60
    dbName=None
    
    dbUser=None
    dbPass=None
    dbUser_env=None
    dbPass_env=None
    runlog=None

    try:
        opts, args = getopt.getopt(sys.argv[1:],PARAM_SHORT_ARG,PARAM_LONG_ARG.keys())
    except getopt.GetoptError:
        traceback.print_exc()
        printHelp()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            printHelp()
            sys.exit()
        elif opt in ("-b", "--bind"):
            bind = arg
        elif opt in ("-b", "--ip"):
            ip = arg
        elif opt in ("-b", "--port"):
            port = arg
        elif opt in ("-c", "--config"):
            appconfigpath = arg
        elif opt in ("--guniconfig"):
            guniconfig = arg
        elif opt in ("-w", "--worker"):
            worker = arg
        elif opt in ("-t", "--thread"):
            thread = arg
        elif opt in ("--dbkey"):
            dbkey_env = arg
        elif opt in ("--filekey"):
            filekey_env = arg
        elif opt in ("--cert"):
            cert_env = arg
        elif opt in ("--key"):
            cert_key_env = arg
        elif opt in ("--output"):
            workingdir = arg
        elif opt in ("--dbname"):
            dbName = arg
        elif opt in ("--dbuser"):
            dbUser_env = arg
        elif opt in ("--dbpass"):
            dbPass_env = arg
        elif opt in ("--log"):
            runlog = arg
    cert_env = cert_env if cert_env is not None else CERT_ENV
    cert_key_env = cert_key_env if cert_key_env is not None else CERT_KEY_ENV
    dbkey_env = dbkey_env if dbkey_env is not None else DATABASE_ENV
    filekey_env = filekey_env if filekey_env is not None else STORAGE_ENV
    dbUser_env = dbUser_env if dbUser_env is not None else DBUSER_ENV
    dbPass_env = dbPass_env if dbPass_env is not None else DBPASS_ENV

    cert_path = os.getenv(cert_env)
    cert_key_path = os.getenv(cert_key_env) if cert_key_env is not None else None
    dbkey = os.getenv(dbkey_env) if dbkey_env is not None else None
    filekey = os.getenv(filekey_env) if filekey_env is not None else None
    dbUser = os.getenv(dbUser_env) if dbUser_env is not None else None
    dbPass = os.getenv(dbPass_env) if dbPass_env is not None else None

    if (DEBUG): logD("!!!!!!!!!!!APP IS STARTED IN DEBUG MODE!!!!!!!!!!!")
    if (DEBUG): logD("!!!!!!!!!!!APP IS STARTED IN DEBUG MODE!!!!!!!!!!!")
    if (DEBUG): logD("!!!!!!!!!!!APP IS STARTED IN DEBUG MODE!!!!!!!!!!!")


    if (DEBUG): logD("cert_path %s" % cert_path)
    if (DEBUG): logD("cert_key_path %s" % cert_key_path)
    if (DEBUG): logD("dbkey %s" % dbkey)
    if (DEBUG): logD("filekey %s" % filekey)

    if (DEBUG): logD("os.environ %s" % str(os.environ))

    application = app.create_app(
        db=dbkey, 
        file=filekey, 
        workingdir=workingdir,
        appconfigPath=appconfigpath, 
        dbName=dbName, 
        dbusr=dbUser, 
        dbpass=dbPass,
        runlog=runlog
        )
    
    if bind is None:
        from server.app import appconfig
        bind = '%s:%s' % (appconfig.get_ip(), appconfig.get_port())
    
    options = {
        # 'bind': '%s:%s' % (common.get_ip(), '8080'),
        # 'workers': number_of_workers(),
        'bind': bind,
        'workers': worker,
        'timeout': timeout,
        'config': guniconfig,
        'certfile': cert_path,
        'keyfile': cert_key_path,
        'preload_app': True,
        'threads': number_of_thread(),
    }
    if cert_env is not None:
        os.unsetenv(cert_env)
        if cert_env in os.environ:
            del os.environ[cert_env] 

    if cert_key_env is not None:
        os.unsetenv(cert_key_env)
        if cert_key_env in os.environ:
            del os.environ[cert_key_env] 

    if dbkey_env is not None:
        os.unsetenv(dbkey_env)
        if dbkey_env in os.environ:
            del os.environ[dbkey_env] 

    if filekey_env is not None:
        os.unsetenv(filekey_env)
        if filekey_env in os.environ:
            del os.environ[filekey_env] 
    
    
    if dbUser_env is not None:
        os.unsetenv(dbUser_env)
        if dbUser_env in os.environ:
            del os.environ[dbUser_env] 


    if dbPass_env is not None:
        os.unsetenv(dbPass_env)
        if dbPass_env in os.environ:
            del os.environ[dbPass_env] 

    if (DEBUG): logD("os.environ %s" % str(os.environ))

    if (DEBUG): logD(options)
    applog.log("Start app, workers: %d, addr: %s, threads: %s" % (worker, bind, thread))
    StandaloneApplication(application, options).run()


#   config: None
#   bind: ['0.0.0.0:5000']
#   backlog: 2048
#   workers: 1
#   worker_class: sync
#   threads: 1
#   worker_connections: 1000
#   max_requests: 0
#   max_requests_jitter: 0
#   timeout: 30
#   graceful_timeout: 30
#   keepalive: 2
#   limit_request_line: 4094
#   limit_request_fields: 100
#   limit_request_field_size: 8190
#   reload: False
#   reload_engine: auto
#   reload_extra_files: []
#   spew: False
#   check_config: False
#   preload_app: False
#   sendfile: None
#   reuse_port: False
#   chdir: /home/dima/work/gunicorn
#   daemon: False
#   raw_env: []
#   pidfile: None
#   worker_tmp_dir: None
#   user: 1000
#   group: 985
#   umask: 0
#   initgroups: False
#   tmp_upload_dir: None
#   secure_scheme_headers: {'X-FORWARDED-PROTOCOL': 'ssl', 'X-FORWARDED-PROTO': 'https', 'X-FORWARDED-SSL': 'on'}
#   forwarded_allow_ips: ['127.0.0.1']
#   accesslog: None
#   disable_redirect_access_to_syslog: False
#   access_log_format: %(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"
#   errorlog: -
#   loglevel: debug
#   capture_output: False
#   logger_class: gunicorn.glogging.Logger
#   logconfig: None
#   logconfig_dict: {}
#   syslog_addr: udp://localhost:514
#   syslog: False
#   syslog_prefix: None
#   syslog_facility: user
#   enable_stdio_inheritance: False
#   statsd_host: None
#   statsd_prefix: 
#   proc_name: None
#   default_proc_name: hello
#   pythonpath: None
#   paste: None
#   on_starting: <function OnStarting.on_starting at 0x7f9757112d08>
#   on_reload: <function OnReload.on_reload at 0x7f9757112e18>
#   when_ready: <function WhenReady.when_ready at 0x7f9757112f28>
#   pre_fork: <function Prefork.pre_fork at 0x7f9756c230d0>
#   post_fork: <function Postfork.post_fork at 0x7f9756c231e0>
#   post_worker_init: <function PostWorkerInit.post_worker_init at 0x7f9756c232f0>
#   worker_int: <function WorkerInt.worker_int at 0x7f9756c23400>
#   worker_abort: <function WorkerAbort.worker_abort at 0x7f9756c23510>
#   pre_exec: <function PreExec.pre_exec at 0x7f9756c23620>
#   pre_request: <function PreRequest.pre_request at 0x7f9756c23730>
#   post_request: <function PostRequest.post_request at 0x7f9756c237b8>
#   child_exit: <function ChildExit.child_exit at 0x7f9756c238c8>
#   worker_exit: <function WorkerExit.worker_exit at 0x7f9756c239d8>
#   nworkers_changed: <function NumWorkersChanged.nworkers_changed at 0x7f9756c23ae8>
#   on_exit: <function OnExit.on_exit at 0x7f9756c23bf8>
#   proxy_protocol: False
#   proxy_allow_ips: ['127.0.0.1']
#   keyfile: None
#   certfile: None
#   ssl_version: 2
#   cert_reqs: 0
#   ca_certs: None
#   suppress_ragged_eofs: True
#   do_handshake_on_connect: False
#   ciphers: TLSv1
#   raw_paste_global_conf: []