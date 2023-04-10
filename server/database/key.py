#!/usr/bin/env python
#
#  KEY OBJECT
#

# from server.app import app
import os
from server import applog as applog 
from server import common as common
import traceback
from .db_mgr import db


# WARINIG: DUE TO KEY IS VERY CRITICAL DATA, SO IT'S SHOULD NOT BE DELETED, AND WELL PROTECTED
# KEY IS MARKED AS DELETE ONLY, CAN BE RECOVERED WHEN NEEDED

#TODO: ENCRYPT KEY DATA

# Key status (ready, not ready, deleted)
KEY_STATUS_NOT_READY = 0
KEY_STATUS_READY = 1
KEY_STATUS_DELETED = -1

# algorithm list
ALG_LIST = ["aes", "rsa"]

# data type: raw or file
# TODO: support both of them??:
KEY_DATA_TYPE_RAW = 0
KEY_DATA_TYPE_FILE = 1

# source of key, for informative purpose
KEY_SOURCE_GENERATE_API = 0
KEY_SOURCE_GENERATE_WEB = 1
KEY_SOURCE_IMPORT_API = 2
KEY_SOURCE_IMPORT_WEB = 3

KEY_STATUS_CNAME = {
    KEY_STATUS_NOT_READY:"No ready",
    KEY_STATUS_READY:"Ready",
    KEY_STATUS_DELETED:"Deleted",
}

# File object, embedded in key
class KeyFile(db.EmbeddedDocument):
    name = db.StringField() # file name
    path = db.StringField() # RELATIVE file path, with root dir of application
    fid = db.StringField()
    metadata = db.StringField() # backup meta info on db
    type = db.StringField() # File type (pem, pub, plain, etc.)

# Key object
# Key is unique with name + project (tbox, ...) + model (vf32, ...)
# unique is checked by software
class Key(db.Document):
    name = db.StringField(required=True) # Key name
    tag = db.StringField() # tag
    alg = db.StringField(required=True) # algrithm (i.e. aes, rsa)
    data = db.StringField(required=True) # key data if file is not use
    data_type = db.IntField() # type of data, raw or file
    files = db.ListField(db.EmbeddedDocumentField(KeyFile)) # list of key file if any
    key_source = db.IntField() # source of key (key imported/generated from web, api call,e tc.)
    # password & salt of key if any 
    # TODO: encrypt this
    pwd = db.StringField()
    salt = db.StringField()

    # Hint
    hint = db.StringField()

    # Project and model that key belongs to, unique with name, model
    project = db.StringField()
    model = db.StringField()

    # created time
    created_time = db.DateTimeField()

    #last update time of key (i.e if key is replace, modified, etc)
    # TODO implement it
    last_update_time = db.DateTimeField()

    # user id of whom created this key
    # TODO implement it
    created_by = db.StringField()

    # user id of whom updated this key
    # TODO implement it
    last_update_by = db.StringField()

    # key history
    history = db.StringField()

    # key status
    # TODO implement it CARREFULLY
    status = db.IntField(default=KEY_STATUS_NOT_READY)
    
    # meta = {'background': False}
    encrypted = db.BooleanField(default=False)

    # default for model-project-
    isdefault = db.BooleanField(default=False)
    
    # target tool to use this key
    target_tool = db.StringField() # list of supported sign tool, in string format, i.e. ['tbox','renesas']

    policy = db.StringField()

    # hash with secret key for important info: project, model, policy
    signature = db.StringField()
    metadata = db.StringField() # meta/additional info for this key
    target_keytool = db.StringField() # list of supported key tool, in string format, i.e. ['tbox','renesas']

    rootKeyId = db.StringField(default=None) # parent/root key id if any
    pubfids = db.ListField(db.StringField(),default=None) # list of public file can be downloaded freely witout policy
    title = db.StringField() # Key title.
    def toString(self):
        strv = ""
        strv += "name: %s\n" % self.name
        strv += "tag: %s\n" % self.tag
        strv += "data_type: %s\n" % self.data_type
        strv += "title: %s\n" % self.title if self.title is not None else ""
        strv += "id: %s\n" % self.id
        strv += "hint: %s\n" % self.hint
        strv += "status: %s\n" % self.status
        strv += "project: %s\n" % self.project
        strv += "model: %s\n" % self.model
        strv += "encrypted: %s\n" % self.encrypted
        strv += "rootKeyId: %s\n" % str(self.rootKeyId) if self.rootKeyId is not None else ""
        strv += "target_keytool: %s\n" % str(self.target_keytool) if self.target_keytool is not None else ""
        strv += "target_tool: %s\n" % str(self.target_tool) if self.target_tool is not None else ""
        return strv

