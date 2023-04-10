# from .app import getRootDataDir
# from .app import get_resp
# from .app import app

# from flask import Flask

# app = Flask(__name__)

# import server.app

# from .app import app

# from flask import Flask
# STATIC_FOLDER=None
# TEMPLATE_FOLDER=None
# BASE_DIR = ROOT_DIR
# if hasattr(sys, '_MEIPASS'): 
#     BASE_DIR =  sys._MEIPASS
# STATIC_FOLDER = os.path.join(BASE_DIR, 'static')
# TEMPLATE_FOLDER = os.path.join(BASE_DIR, 'templates')


# #global object 
# app = Flask(__name__, template_folder=TEMPLATE_FOLDER, static_folder=STATIC_FOLDER)
# app.config["DEBUG"] = DEBUG

# app = Flask(__name__)
# api = Api(app)

# import server.login.login_api_handling
# import server.sign.sign_api_handling
# import fota.fota_api_handling
# import key.key_api_handling
# import server.database.db_api_handling
# import admin.admin_api_handling
# import doc.doc_api_handling

from server.login import login
from server import applog
# from server import app
from server import common