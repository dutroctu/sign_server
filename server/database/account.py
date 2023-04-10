#!/usr/bin/env python
#
#  Account info 
#

# from server.app import app
import os
from server import common as common
import traceback
from .db_mgr import db

MAX_SESSION_TIME_MS = (3 * 60 * 1000)

# Account type
ACCOUNT_TYPE_UNKNOWN = 0
ACCOUNT_TYPE_GUEST = 1 # Guest, may view only, do nothing
ACCOUNT_TYPE_SIGNER = 2 # Upload code to signing only
ACCOUNT_TYPE_USER = 3 # can import key
ACCOUNT_TYPE_MOD = 4 # can manage key
ACCOUNT_TYPE_ADMIN = 5 # highest role

# TODO: Support policy group?

# Name to ID
ACCOUNT_TYPE_NAME_ID = {
    "ACCOUNT_TYPE_UNKNOWN":ACCOUNT_TYPE_UNKNOWN,
    "ACCOUNT_TYPE_GUEST":ACCOUNT_TYPE_GUEST,
    "ACCOUNT_TYPE_SIGNER":ACCOUNT_TYPE_SIGNER,
    "ACCOUNT_TYPE_USER":ACCOUNT_TYPE_USER,
    "ACCOUNT_TYPE_MOD":ACCOUNT_TYPE_MOD,
    "ACCOUNT_TYPE_ADMIN":ACCOUNT_TYPE_ADMIN,
}

# ID to Name
ACCOUNT_TYPE_ID_NAME = {
    ACCOUNT_TYPE_UNKNOWN:"ACCOUNT_TYPE_UNKNOWN",
    ACCOUNT_TYPE_GUEST:"ACCOUNT_TYPE_GUEST",
    ACCOUNT_TYPE_SIGNER:"ACCOUNT_TYPE_SIGNER",
    ACCOUNT_TYPE_USER:"ACCOUNT_TYPE_USER",
    ACCOUNT_TYPE_MOD:"ACCOUNT_TYPE_MOD",
    ACCOUNT_TYPE_ADMIN:"ACCOUNT_TYPE_ADMIN",
}

# ID to Common Name
ACCOUNT_TYPE_ID_CNAME = {
    ACCOUNT_TYPE_UNKNOWN:"Unknown",
    ACCOUNT_TYPE_GUEST:"Guest",
    ACCOUNT_TYPE_SIGNER:"Signer",
    ACCOUNT_TYPE_USER:"User",
    ACCOUNT_TYPE_MOD:"Moderator",
    ACCOUNT_TYPE_ADMIN:"Admin",
}


# Account status
ACCOUNT_STATUS_NOT_READY = 0
ACCOUNT_STATUS_READY = 1
ACCOUNT_STATUS_DEACTIVE = -1
ACCOUNT_STATUS_DELETE = -2 # need delete state? deactive status is enough, i think

# status to Common Name
ACCOUNT_STATUS_CNAME = {
    ACCOUNT_STATUS_NOT_READY:"No ready",
    ACCOUNT_STATUS_READY:"Ready",
    ACCOUNT_STATUS_DEACTIVE:"Deactive",
    ACCOUNT_STATUS_DELETE:"Deleted",
}


# Account
class Account(db.Document):
    # User name, unique. Not set unique flag, as account will be deactive/delete, but still keep data in database. 
    # Unique will be checked by software
    username = db.StringField(required=True)

    # Full name
    fullname = db.StringField(required=True)

    # TODO: Should change to another method?
    # Password, MUST be in hash format
    password = db.StringField(required=True)
    # Salt, used to calc hash of password
    salt = db.StringField(required=True)

    # Email
    email = db.StringField()
    # Phoe number
    phone = db.StringField()

    # Account type
    type = db.IntField(default=ACCOUNT_TYPE_UNKNOWN)

    # Accoutn status/statue
    status = db.IntField(default=ACCOUNT_STATUS_NOT_READY)

    # Note for account
    note = db.StringField()

    # Created time
    created_time = db.DateTimeField()

    # Last login time
    # TODO: implement it
    last_login_time = db.DateTimeField()

    # Accont created by?
    # TODO: implement it
    created_by = db.StringField()

    # History of account usage
    history = db.StringField()

    # Mark if account is using default password
    default_password = db.BooleanField(default=True)

    encrypted = db.BooleanField(default=False)

    failed_counter = db.IntField(default=0)

    # policy group id, used to manage permission for each account
    # TODO: just reserve for future use, implement it
    policy_group = db.IntField(default=0)

    sshrsa = db.ListField(db.StringField()) # list of ssh id-rsa fid

    # signature for each items, to make sure integrity of this item
    signature = db.StringField()

    def toString(self):
        str = ""
        str += "id: %s;\n" % self.id
        str += "username: %s;\n" % self.username
        str += "status: %d;\n" % self.status
        str += "type: %d (%s);\n" % (self.type, ACCOUNT_TYPE_ID_NAME[self.type])
        return str
