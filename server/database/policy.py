#!/usr/bin/env python
#
#  Account info 
#

# from server.app import app
import os
from server import common as common
import traceback
from .db_mgr import db

# TODO:  to be updated 
# resource: list up resource, with actions
# label (unique), module, resource name, action list (download:allow/deny, delete:allow/deny, create:allow/deny, update:allow/deny, change:allow/deny, view:allow/deny) 

# caller:
# <type>

# user_policy:
# each row: and condition
# in many row: or condition
# <resource label>, <action list>, <rule>{"authen":login, "account":<admin, xxx, rsa:require, ip:xxx/any, port:xxx/any} (and condition), signature

# check rule(username, rsa, ip, port, account type, logined or not)
class Policy(db.Document):
    # "caller" have "rule" to access "resource"
    # information are in json format


    # resource: {["module":xxx, "default":{<rule>}, "resource":[{"name":xxx, "default":{rule}}]}
    resource = db.StringField(required=True)

    # caller: {"username":xxx, "ip":xxx, "port":xxx, "rsa":[xxx, xxx], "authen":[username|ip|port|rsa]}
    caller = db.StringField(required=True)


    # rule: allow/deny/floating
    # rule: {"default":allow/deny, "authen":[username|rsa|xxx], "action":[{"download":allow/deny, "delete":allow/deny}]}
    rule = db.StringField(required=True)
    signature = db.StringField()
    created_time = db.DateTimeField()
    last_updated = db.DateTimeField()

    def toString(self):
        str = ""
        # str += "id: %s;\n" % self.id
        # str += "username: %s;\n" % self.username
        # str += "status: %d;\n" % self.status
        # str += "type: %d (%s);\n" % (self.type, ACCOUNT_TYPE_ID_NAME[self.type])
        return str
