#!/usr/bin/env python
#
#  MANAGE SESSION
#


import os
from server import applog as applog 
import uuid
from server import common as common
from server.applog import logD
from server.app import DEBUG

MAX_SESSION_TIME_MS = (3 * 60 * 1000)
MAX_SESSION_COUNT_CHECK = (100)

# Session data
class SessionData (object):
    def clean(self):
        pass

# Session
class Session:
    uuid = None
    created_time = 0
    updated_time = 0
    data = None
    def __init__(self, uuid, created_time = 0):
        self.uuid = uuid
        if (created_time == 0):
            created_time = common.current_milli_time()
        
        self.created_time = self.updated_time = created_time

    def update_time(self, update_time):
        self.updated_time  = update_time

    def set_data(self, data):
        self.data  = data

    def toString(self, isFull=False):
        str = ""
        str += "uuid: %s, " % self.uuid
        if isFull:
            str += "created_time: %d, " % self.created_time
            str += "updated_time: %d, " % self.updated_time
        str += "\n"
        return str

# Session Management
class SessionMng:
    SessionList = {}
    
    
    #TODO: do it async
    # check to clear session in list
    def check_to_clear_session(self):
        keys = list(self.SessionList.keys())
        for key in keys:
            session = self.SessionList[key]
            if (session is not None):
                current_time = common.current_milli_time()
                if (session.updated_time + MAX_SESSION_TIME_MS) < current_time:
                    if (DEBUG): logD("Delete session %s (current no %d) (current %d, updated %d" %(key, len(self.SessionList), current_time, session.updated_time))
                    self.clear_session(session, False)
                    if (DEBUG): logD("After delete no %d" % (len(self.SessionList)))


    # dump session info, if session id is none, dump all
    def dump(self, sessionid = None):
        if (sessionid is not None) and len(sessionid) > 0:
            session = self.get_session(sessionid)
            if (session is not None):
                if (DEBUG): logD("Session %s: %s" % (sessionid, session.toString()))
                return
            else:
                if (DEBUG): logD("Session %s: Not found" % sessionid)
        if (DEBUG): logD("No. session %d" % len(self.SessionList))
        for session in self.SessionList:
            if (session is not None):
                if (DEBUG): logD("%s" % session.toString())
        
    # get session, if session  id is none, generate new one
    def get_session(self, sessionid=None):
        session = None
        if (sessionid is None):
            count = 0
            while count < MAX_SESSION_COUNT_CHECK:
                sessionid = str(uuid.uuid4())
                # TODO: still there is the risk that when sessionid is not add to session list until push_session is call
                # FIXME please
                if sessionid not in self.SessionList:
                    break
                else:
                    count += 1
                    #TODO: wait for a while? or add salt to uuid creation?
            if (count < MAX_SESSION_COUNT_CHECK):
                if (DEBUG): logD("Generate new session %s" % sessionid)
                session = Session(sessionid)
            else:
                if (DEBUG): logD("Failed to create session id, reach max attemp %d" % count)
                session = None
        else :
            if (DEBUG): logD("Search session for uuid %s" % sessionid)
            if (sessionid in self.SessionList):
                if (DEBUG): logD("Found session %s" % sessionid)
                session = self.SessionList[sessionid]
                if (DEBUG): logD("session %s" % ("valid" if session is not None else "invalid"))
            else:
                applog.logE("Not found session for uuid %s" % sessionid)
                session = None
        
        return session

    # push session
    def push_session(self, session):
        if (DEBUG): logD("push_session %s" % (session.uuid if session is not None else "empty"))
        if (session is None):
            if (DEBUG): logD("Invalid session")
            return False
        else :
            if (DEBUG): logD("Push session for uuid %s" % session.uuid)
            self.SessionList[session.uuid] = session
        
        self.check_to_clear_session()
        return session

    # clear session
    def clear_session(self, session, auto_clean = True):
        if (DEBUG): logD("Clear session %d" % (auto_clean))
        if (session is None):
            if (DEBUG): logD("Invalid session")
            return False
        else :
            if (DEBUG): logD("Clear session for uuid %s" % session.uuid)
            if isinstance(session, SessionData): # if data is Session data, call clear function
                session.clean()
            if (session.uuid in self.SessionList): # if session is in list, remove from list
                self.SessionList.pop(session.uuid)
            if (DEBUG): logD("After delete no %d" % (len(self.SessionList)))
        
        if (auto_clean == True): #warning: deadlock
            self.check_to_clear_session()
        return True

    # clear session
    def clear_sessionId(self, sessionid, auto_clean = True):
        if (DEBUG): logD("clear_sessionId %d" % (auto_clean))
        if (sessionid is None):
            if (DEBUG): logD("Invalid session")
            return False
        else :
            if (DEBUG): logD("Clear sessionid for uuid %s" % sessionid)
            session = None
            if (sessionid in self.SessionList): # get session
                session = self.get_session(session.uuid)
            if (session is not None): # if session is in list, remove from list
                if isinstance(session, SessionData): # if data is Session data, call clear function
                    session.clean()            
                self.SessionList.pop(session.uuid)
            if (DEBUG): logD("After delete remain session: %d" % (len(self.SessionList)))
        
        if (auto_clean == True): #warning: deadlock
            self.check_to_clear_session()
        return True
