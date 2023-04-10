#!/usr/bin/env python
#
#  SYSTEM MONITOR
#


from imp import acquire_lock
from logging import CRITICAL
from flask import redirect, url_for
from server.app import DEBUG

import os
# from server.applog import log
from server.applog import logE
from server.applog import logD
from server.applog import Log
from server import common as common
from server.app import DEBUG
from server.app import getRootDataDir
from server.app import getRootTempDir
from server.app import getRootLogDir
from server.app import getRootDownloadDir
from server.app import MONITOR_WAIT_TIMEOUT
from server.monitor.system_report import INCIDENT_SEVERITY_CRITICAL
from server.monitor.system_report import INCIDENT_SEVERITY_LOW
from server.monitor.system_report import INCIDENT_SEVERITY_MIDDLE
from server.monitor.system_report import sysReport

from threading import Thread, Lock
from time import sleep
import threading

import traceback
from multiprocessing import Array, Manager, Value
import multiprocessing as mp
from multiprocessing import Process, Queue
import socket

import json


TAG = "SystemMon"

log = Log(TAG)

# Folder to store run-time data of system monitor
SYSTEM_REPORT = ".monitor"

SYSTEM_REPORT_DIRECTORY = os.path.join(getRootLogDir(), SYSTEM_REPORT)

DUMP_QUEUE_LOG_FNAME = "dump_req_queue.log"
DAYS_MIN = 0
DAYS_MAX = 100

# Max waiting time to check queue.
# to avoid "dead" log forover
QUEUE_DEFAULT_TIMEOUT = MONITOR_WAIT_TIMEOUT


# Unix Socket to communicate with client
# FIXME
# FIXME
# FIXME
# WARNING: SHOULD PROTECT THIS SOCKET. CURRENTLY, protected via DAC only, is it enough?????
# If malicious client try to access to this note, something stupid may happend
SOCKET_ADDRESS = "./uds_socket"

# Request to delete file
REQ_ID_DELETE = 1

# Request to stop monitor
REQ_ID_STOP = 2

REQ_ID_DUMP_QUEUE = 3

# If connection with client is failed due to stupid issue, this is max time we retry, to avoid 
# Monitor Service consume to much CPU
# Monitor Service has lower priority that others, don't make it impact to other operation
MAX_CONNECT_EXCEPTION = 100



# Monitor request object
class MonRq(object):
    name = ""
    caller = 0
    timeout = 0
    addedTime = 0
    expiredTime = 0
    data = None
    process_callback = None

    def __init__(self, name=None):
        self.name = name
        self.process_callback = None
        self.timeout = 0
        self.caller = 0
        self.addedTime = 0
        self.expiredTime = 0
        self.data = None

#
# MAIN class of System monitor
# System Monitor shall run on separate process, communicate with others via unix socket
# 2 threads:
# - Main thread: To receive request from client via socket, parse/build data into request, and add to request queue
# - Request thead: Thread to handle request in request queue
#
class SystemMonitor(object):

    #https://docs.python.org/3/library/queue.html
    # request_queue = None
    process_req_queue = None # Queue to receive request from client
    
    
    request_queue = [] # Queue to handle request
    request_thread = None # Thread to handle request
    request_thread_shouldStop = True # handling request should stop or not?

    cond_req = None
    lastTimeMs = 0
    nextRunTimeMs = 0
    mutex_req_thread = None
    mutex_req_thread_id = 0

    # Worker process, it's Monitor System Process!!!!
    workerProcess = None
    running_flag = mp.Value("i", 1) # Should stop monitoring??
    myPid = mp.Value("i", 0)
    parent_pid = 0


    def __init__(self):
        self.request_queue = []
        self.process_req_queue = Queue()
        self.request_thread_shouldStop = True
        self.mutex_req_thread = Lock()
        self.mutex_req_thread_id = 0

        log.i("INIT SYSTEM MONITOR")
        log.i("QUEUE_DEFAULT_TIMEOUT %d ms" % QUEUE_DEFAULT_TIMEOUT)

        

    # Start thread to handle request
    def startReqHandleThread(self):
        self.request_thread = Thread(target=self.thread_handle_req)
        self.request_thread_shouldStop = False
        self.request_thread.setDaemon(True) # Kill me when parent die
        self.request_thread.start()



    # Fork/start other process to handle monitoring service
    # WHY? 
    # 1st: safe for main process
    # 2nd: gunicorn fork to multiple worker process, need a separate process to handle monitor task
    def startMonPrcess(self):
        ret = common.ERR_NONE
        pid = os.getpid()
        log.i("startMonPrcess from pid %d" % os.getpid())

        self.parent_pid = pid
        # Unlink existing socket if exit
        try:
            
            # we use unix socket to handler our process
            if os.path.exists(SOCKET_ADDRESS):
                log.i("Unlink %s" % SOCKET_ADDRESS)
                os.unlink(SOCKET_ADDRESS)
            
        except OSError:
            traceback.print_exc()
            
            if os.path.exists(SOCKET_ADDRESS):
                ret = common.ERR_EXISTED
                log.e("Unlink failed, address still exist, stupid")

        if (ret == common.ERR_NONE):
            try:
                log.i("Start monitor process")
                self.workerProcess = mp.Process(target=self.process_handler, args=(self.running_flag, self.process_req_queue, self.myPid))
                self.workerProcess.daemon = True # termimated if parent process die....
                self.workerProcess.start() # well done, start it
                ret = common.ERR_NONE
            except:
                traceback.print_exc()
                ret = common.ERR_EXCEPTION
        

        return ret


    # Entry point of monitor process
    def process_handler(self, running_flag, q, mypid):
        log.i("process_handler")
        
        ret = common.ERR_NONE
        exception_count = 0

        mypid = os.getpid()
        log.i("My PID: %d" % mypid)
        
        # Assume that already unlink, is it safe?
        # FIXME please
        # os.unlink(SOCKET_ADDRESS)
        s = None
        try:
            # we use unix socket to handler our process
            log.i("Create unix socket, address %s" % SOCKET_ADDRESS, True)
            s = socket.socket(
                socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(SOCKET_ADDRESS)
            s.listen(1)
            # FIXME please
            # FIXME
            # FIXME
            # using socket without checking caller is verify danger, may be used by other to "hacking" me
            # Add authentication when receiving data from caller, please.....
            # FIXME
        except:
            traceback.print_exc()
            log.e("Something when wrong when start listen unix socket", True)
            sysReport().reportIncident(INCIDENT_SEVERITY_CRITICAL, None, "Something when wrong when start listen unix socket %s" % SOCKET_ADDRESS)
            ret = common.ERR_EXCEPTION
        
        if ret == common.ERR_NONE:
            # lets start request handler thread
            self.startReqHandleThread()
            
            while running_flag.value == 1 and exception_count < MAX_CONNECT_EXCEPTION:
                connection = None
                try: 

                    if s is None: # it should not occur, honestly
                        log.i("Something wrong, socket is None, re-create")
                        # if socket exist, remove it
                        if os.path.exists(SOCKET_ADDRESS):
                            log.i("Unlink %s" % SOCKET_ADDRESS)
                            try:
                                os.unlink(SOCKET_ADDRESS)
                            except:
                                traceback.print_exc()
                                # stupid, do nothing
                                # is it safe?
                        
                        # try to re-connect
                        s = socket.socket(
                                socket.AF_UNIX, socket.SOCK_STREAM)
                        s.bind(SOCKET_ADDRESS)
                        s.listen(1)
                        # if exception occurs again, cache and retry

                    log.i("Wait for connection from client")
                    connection, client_address = s.accept()
                    if running_flag.value != 1: # should out????
                        break
                
                    log.i("Connect from %s" % client_address)

                    # FIXME 2048 bytes are enough?????
                    data = connection.recv(2048)
                    # TODO: handle the case that connection is failed?
                    # it's danger if looping forevevr

                    if running_flag.value != 1:
                        break

                    if data and len(data) > 0:
                        try: # we got data to handle now
                            log.i("We got something to handle now")
                            # parse to json
                            jdata = json.loads(data)
                            name = jdata["name"] if "name" in jdata else None
                            caller = jdata["caller"] if "caller" in jdata and jdata["caller"] > 0 else 0
                            data = jdata["data"] if "data" in jdata else None
                            timeout = jdata["timeout"] if "timeout" in jdata and jdata["timeout"] > 0 else 0
                            req = jdata["req"] if "req" in jdata and jdata["req"] > 0 else 0

                            if req == REQ_ID_STOP: # stop me
                                break

                            # Build and add to request queue
                            self.buildAddReq(name, caller, data, timeout, req)

                        except:
                            traceback.print_exc()
                            # TODO: should stop????
                            
                    exception_count = 0
                except KeyboardInterrupt:
                    log.e("Key interrupt, stop")
                    traceback.print_exc()
                    break
                except:
                    # Some f*ck issue here, let's retry
                    # socket file still available????

                    log.e("Exception when waiting socket")
                    traceback.print_exc()
                    exception_count += 1

                    # ok guys, let's try something here:
                    if not os.path.exists(SOCKET_ADDRESS):
                        # close old socke, try new one later on
                        try:
                            if s is not None:
                                s.close()
                                s = None
                        except:
                            traceback.print_exc() # oh shit
                finally:
                    # Clean up the connection
                    if connection is not None:
                        connection.close()
        
        log.i("Process handling exit")
        if s is not None:
            log.d("close socket")
            s.close()
        try:
            log.d("unlock address")
            os.unlink(SOCKET_ADDRESS)
        except:
            traceback.print_exc()

        log.d("stop request thread")
        self.stopRequestThread()
                
        # TODO: should restart it??????
        sysReport().reportIncident(INCIDENT_SEVERITY_LOW, None, "Request Process Handler exit, exception count = %d" % exception_count)

    # Get lock
    def acquireMutex(self):
        # FIXME: Is it safe? as concorrent may occur when checking mutex_req_thread_id
        if self.mutex_req_thread_id != 0 and self.mutex_req_thread_id == threading.get_ident():
            log.e("Deadlock!!!!, call lock in same thread")
        else:
            self.mutex_req_thread.acquire()
            self.mutex_req_thread_id  = threading.get_ident()
            log.d("Acquire mutex in thread id %d" % self.mutex_req_thread_id )
    
    # Release lock
    def releaseMutex(self):
        self.mutex_req_thread_id = 0
        self.mutex_req_thread.release()
        log.d("Release mutex")

    # Check to handle request if any
    def check2RunReq(self):
        log.d(">>> check2RunReq")
        minwaitime = QUEUE_DEFAULT_TIMEOUT
        removeReq = []

        self.acquireMutex()
        request_queue = self.request_queue
        log.d("%d item in queue" % len(request_queue))
        
        try:

            # check item one by one, get minimum waiting time
            for req in request_queue:
                if req is not None and isinstance(req, MonRq):
                    log.d("req.expiredTime %d" % req.expiredTime)
                    
                    currtime = common.current_milli_time()
                    log.d("currtime %d" % currtime)
                    if req.expiredTime <= currtime: # expired, run it
                        log.i("Run request '%s', called from %d" % (req.name, req.caller), True)
                        # call callback
                        if req.process_callback is not None:
                            try:
                                req.process_callback(req.data)
                            except:
                                traceback.print_exc()
                                log.e("Exception when executing request '%s'" % req.name, True)
                        else:
                            log.i("Nothing to be run for %s?" % req.name)
                        removeReq.append(req)
                    else:
                        waitime = req.expiredTime-currtime
                        
                        # try to get min waiting time
                        log.d("waitime %d" % waitime)
                        if waitime < minwaitime:
                            minwaitime = waitime
                else:
                    log.e("Some thing may wrong here, invalid req in queue")
                    removeReq.append(req)


        except:
            log.e("Excepion when queu process")
            traceback.print_exc()
            minwaitime = QUEUE_DEFAULT_TIMEOUT
        
        # something need to remove?
        log.d("%d item to remove" % len(removeReq))
        if len(removeReq) > 0:
            for req in removeReq:
                log.i("Remove request from queue")
                request_queue.remove(req)

        log.d("%d item in queue" % len(request_queue))
        
        self.releaseMutex()

        log.d("minwaitime %d" % minwaitime)
        return minwaitime

    

    # Request thread handler
    def thread_handle_req(self):
        log.i("thread_handle_req")
        while not self.request_thread_shouldStop:
            wait = QUEUE_DEFAULT_TIMEOUT
            try:
                log.i("check to run req")
                wait = self.check2RunReq()
                if wait <= 0:
                    # FIXME: Should stop it?
                    wait = QUEUE_DEFAULT_TIMEOUT
            except KeyboardInterrupt:
                log.i("Exist thread due to key interrupt")
                self.request_thread_shouldStop = True
                break
            except:
                log.e("Excepion when run cyclic")
                traceback.print_exc()
                wait = QUEUE_DEFAULT_TIMEOUT
                # FIXME: Should stop it?
                # self.request_thread_shouldStop = True
                # break
             
            if self.request_thread_shouldStop:
                break
        
            log.d("Sleep in %d ms" % wait)
            self.wait_cond_req(wait)
            


        log.i("thread_handle_req END")

    def getProcessCallback(self, reqId):
        process_callback = None
        # TODO: improve this code
        if reqId == REQ_ID_DELETE:
            process_callback = self.deleteFileDirCallback
        elif reqId == REQ_ID_DUMP_QUEUE:
            process_callback = self.requestToDumpQueue
        else:
            process_callback = None

        return process_callback

    # Build request and add to queue
    def buildAddReq(self, name, caller, data, timeout, reqId):
        log.d("buildAddReq %s" % name)

        req = MonRq()
        req.name = name
        req.caller = caller
        
        req.process_callback = self.getProcessCallback(reqId)
        
        req.timeout = timeout
        req.data = data
        currtime = common.current_milli_time()
        req.addedTime = currtime
        req.expiredTime = currtime + timeout # Assum system time is up-to-date
        # FIXME: overflow expireTime?
        
        # add to queue
        self.acquireMutex()

        log.d("Add req %s at %d, timeout %d ms, expiredTime %d" % (name, currtime, timeout, req.expiredTime))
        self.request_queue.append(req)
        log.d("%d item in queue" % len(self.request_queue))
        
        # TODO: to much request, should remove eldest one????
        
        self.releaseMutex()
        self.release_cond_req()


    # stop request thread
    def stopRequestThread(self):
        log.i("Stop request queue device")
        self.request_thread_shouldStop = True
        self.release_cond_req() #out of wait state
        # if self.request_queue.empty():
        #     self.request_queue.put_nowait(MonRq) # dummy canframe
        return common.ERR_NONE

    # Stop monitoring
    def stop(self):
        log.i("Stop mon")
        self.running_flag = 0
        self.addReq2Queue(REQ_ID_STOP)
        # self.stopRequestThread()

    # requset to delelte file
    def deleteFileDirCallback(self, fpath):
        log.d("deleteFileDirCallback")
        if fpath is not None and len(fpath) > 0 and os.path.exists(fpath):
            # Be care, only delete if path is 
            downloadir = getRootDownloadDir()
            log.d("downloadir %s" % downloadir)
            fullpath = fpath
            if not os.path.isabs(fullpath):
                log.d("Not abs path, convert to abs path")
                fullpath = os.path.abspath(fpath)

            # path is in download folder? (safe to delete)
            # TODO: support more, by adding whitelist folder allow to delete
            if downloadir is not None and len(downloadir) > 0 and fullpath.startswith(downloadir): 
                if os.path.isdir(fullpath):
                    log.i("Remove dir %s" % fullpath)
                    common.rmdirs(fullpath)
                else:
                    log.i("Remove file %s" % fullpath)
                    os.remove(fullpath)
            else:
                log.e("Can not remove '%s', it's not in '%s'" % (fullpath, downloadir), True)
        else:
            log.e("remove request, but file/path see not exist %s" % fpath if fpath is not None else "")

    # path to log file
    def getMonDumpReqQueueFPath(self):
        return os.path.join(SYSTEM_REPORT_DIRECTORY, DUMP_QUEUE_LOG_FNAME)

    # callback to handle dump request queue
    def requestToDumpQueue(self, data):
        log.i("request to dump req queue", True)
        fpath = self.getMonDumpReqQueueFPath()
        try:
            log.d("Write to file %s" % fpath)
            with open(fpath, "w") as fp:
                fp.write("Total req: %d\n" % len(self.request_queue))
                fp.write("Current time: %d ms\n" % common.current_milli_time())
                fp.write("*****\n")
                for req in self.request_queue:
                    fp.write("name: %s\n" % req.name)
                    fp.write("- caller: %d\n" % req.caller)
                    fp.write("- timeout: %d\n" % req.timeout)
                    fp.write("- addedTime: %d ms\n" % req.addedTime)
                    fp.write("- expiredTime: %d ms\n" % req.expiredTime)
        except:
            log.e("Excepion when writing to %s" % fpath)
            traceback.print_exc()

    # Add request to queue
    # Data MUST BE STRING-based
    @staticmethod
    def addReq2Queue(reqId, name = "", data = None, timeout = 0):
        log.d("addReq2Queue")
        ret = common.ERR_NONE
        try:
            # open unix socket to monitor service, and send data to him
            log.i("addReq2Queue, Connect to socket %s" % SOCKET_ADDRESS)
            if os.path.exists(SOCKET_ADDRESS):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(SOCKET_ADDRESS)

                jdata = {
                    "name":name,
                    "caller":os.getpid(),
                    "data":data if data is not None else "", # what happend if data is not string?
                    "timeout":timeout,
                    "req":reqId
                    }
                jstring = json.dumps(jdata)
                s.send(jstring.encode('utf-8'))
                s.close()

                ret = common.ERR_NONE
                log.i("addReq2Queue, Sent request")
            else:
                log.e("seem monitor service die, cannot add request to queue")
                ret = common.ERR_NOT_FOUND
        except:
            log.e("Excepion send request to monitor")
            traceback.print_exc()
            ret = common.ERR_EXCEPTION

        log.d("addReq2Queue END")
        return ret
        
    # add delete request to queue
    @staticmethod
    def addDeleteReq2Queue(fpath, waittime):
        log.i("Add %s to auto delete queue, after %d" % (fpath, waittime))

        if fpath is not None and len(fpath) > 0 and os.path.exists(fpath):
            SystemMonitor.addReq2Queue(REQ_ID_DELETE, name="deletefile %s" % fpath, data = fpath, timeout = waittime)
        else:
            log.e("Req Delete file, but invalid or not exist path? %s" % fpath if fpath is not None else "")

    # Dump request queue
    @staticmethod
    def addDumpReq2Queue():
        log.i("add req to dump queue")
        SystemMonitor.addReq2Queue(REQ_ID_DUMP_QUEUE, name="Dump req queue", data = None, timeout = 0)



    # Wait...wwait...wait
    def wait_cond_req(self, timeout = QUEUE_DEFAULT_TIMEOUT):
        ret = common.ERR_NONE
        if (DEBUG): log.d("Wait condition in %d ms" % timeout)
        try:
            self.cond_req = threading.Condition()
            with self.cond_req:
                waiting = 0.0
                waiting = timeout/1000
                log.d("wait_cond_req %f" % waiting)
                startwait = common.current_milli_time()
                log.d("wait start %d" % startwait)
                if self.cond_req.wait(waiting):
                    ret = common.ERR_NONE
                else:
                    log.d("Wait cond TIMEOUT %f" % waiting)
                    ret = common.ERR_TIMEOUT
                endwait = common.current_milli_time()
                log.d("wait end %d, waited %d" % (endwait, endwait - startwait))
        except:
            log.e("Wait cond TIMEOUT")
            ret = common.ERR_TIMEOUT
        finally:
            self.cond_req = None
        return ret
        
    # release/notify condition
    def release_cond_req(self):
        log.d("release_cond_req")
        if self.cond_req is not None:
            try:
                with self.cond_req:
                    self.cond_req.notify_all()
            except:
                traceback.print_exc()

    # Clearup download folder, return error code and message [err, msg]
    def cleanupDownloadFolder(self, days, requestor = None):
        ret = common.ERR_FAILED
        result = ""
        if (days >= DAYS_MIN) and (days <= DAYS_MAX):
            from server.app import getRootDownloadDir
            from server.app import DOWNLOAD_DIRECTORY_NAME
            fdir = getRootDownloadDir()
            if fdir is not None and len(fdir) > 0 and fdir.endswith(DOWNLOAD_DIRECTORY_NAME) and os.path.exists(fdir) :
                command = "find '%s' -type d -ctime +%d -exec rm -rf {} \;" % (fdir, days)
                log.i("Command %s" % command)
                sysReport().reportIncident(INCIDENT_SEVERITY_CRITICAL, requestor, "Clear up download folder'%s', keep %d days" % (fdir, days))
                cmdRes = common.runCommandWithOutput(command)
                if cmdRes is not None:
                    result = "Cleanup download '%s' in %d days finished, log: \n" % (fdir, days)
                    result += ''.join(cmdRes).strip()
                    ret = common.ERR_NONE
                else:
                    log.e("Run cleaup command failed")
                    result = "Run cleaup failed"
                    ret = common.ERR_FAILED
        else:
            log.e("Run cleaup command, inavlid days %d" % days)
            result = "Run cleaup failed, days must in [%d,%d]" % (DAYS_MIN, DAYS_MAX)
            ret = common.ERR_FAILED
        log.i("cleanupDownloadFolder %s" % result)
        return [ret, result]

    # Check storage size
    def checkStorage(self):

        command = "df -h"
        log.i("checkStorage %s" % command)
        cmdRes = common.runCommandWithOutput(command)
        
        result = "Check Storage: no result"
        if cmdRes is not None:
            result = ''.join(cmdRes).strip()
        else:
            log.e("run df command failed")
        log.i("checkStorage %s" % result)
        return result
    
    # Check dir size
    def checkDirSize(self, fdir, depth=1):
        log.i("checkCheckDirSize")
        result = "Check dir: no result"
        if depth > 10: # max depth is 10
            depth = 10
        if fdir is not None and len(fdir) > 0:
            if os.path.exists(fdir):
                command = "du -h -d %d '%s'" %(depth, fdir)
                log.i("Command %s" % command)
                cmdRes = common.runCommandWithOutput(command)
                if cmdRes is not None:
                    result = ''.join(cmdRes).strip()
                else:
                    log.e("Run du command failed")
                    result = "Run command failed"
            else:
                log.e("%s not exist" % fdir)
                result = "Check dir: not exist"
        else:
            log.e("fdir is invalid")
            result = "Check dir: invalid"

        log.i("checkCheckDirSize %s" % result)
        return result

g_systemmon = None

# Got system monitor object
def sysMon():
    global g_systemmon
    if g_systemmon is None:
        init_system_monitor()

    return g_systemmon


# Init system monitor
def init_system_monitor(app = None):
    log.i("init_system_monitor", toFile=True)

    log.i("Init system monitor dir %s" % SYSTEM_REPORT_DIRECTORY, True)
    if not os.path.exists(SYSTEM_REPORT_DIRECTORY):
        os.makedirs(SYSTEM_REPORT_DIRECTORY)
    
    global g_systemmon
    g_systemmon = SystemMonitor()

    # Start system monitor process
    # Monitoring shall be running on different process, and communicate via unix socket
    ret = g_systemmon.startMonPrcess()
    
    return ret

# Stop system monitor
def stop_system_monitor(app=None):
    log.i("stop_system_monitor")
    global g_systemmon
    if g_systemmon is not None:
        g_systemmon.stop()