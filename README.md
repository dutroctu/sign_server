# Introduction 
SIGNING SERVER
Develop basing on python and flask

Port is 8888 can be changed according setting

# Document
Design document: https://vingroupjsc.sharepoint.com/sites/TTNTDTOT_SW_Security/Shared%20Documents/General/design/simple_signing_server/210225_VF_TTGTKNTT_signing_server_design_V1.xlsx

Link:
https://vingroupjsc.sharepoint.com/:x:/r/sites/TTNTDTOT_SW_Security/Shared%20Documents/General/design/simple_signing_server/210225_VF_TTGTKNTT_signing_server_design_V1.xlsx?d=w97db1ea4f33448419fa0a44e6e72e6de&csf=1&web=1&e=EbONxK

# Enviroment
Signing server run on
- Ubuntu 64 bit 18.04 and above
Requires following main modules:
- Python3
- Python3 Gnuicorn: for HTTP Web gateway
- Python3 Flask-related modules: For server app implementation
- pyinstaller: For compiling python code to binary
- MongoDB: for database


# Getting Started
## APT
- mongodb
- gunicorn
- python3
- python3-pip
- python3-dev
- gcc
- g++
- pkg-config
- libcairo2-dev libjpeg-dev libgif-dev
- libcups2-dev
- python3-venv
- libapache2-mod-wsgi-py3

Depend on signging tool, additional package may be required to install.

Example
```
$ sudo apt install -y mongodb
$ sudo apt install -y build-essential python3-dev
```

## Python package
Some python package may require to upgrade pip

```
$pip3 install --upgrade pip
```

``` 
pip3 install flask
pip3 install jsonify
pip3 install flask-restful
pip3 install uuid
pip3 install wheel
pip3 install flask-mongoengine
pip3 install Flask-PyMongo
pip3 install PyMongo==3.3
pip3 install flask-login
pip3 install setuptools
pip3 install setuptools_rust
pip3 install cryptography
pip3 install pycrypto
pip3 install pyAesCrypt (may require upgrade pip: pip3 install --upgrade pip)
pip3 install pycryptodome
pip3 install pyinstaller
pip3 install markdown
pip3 install MarkupSafe
pip3 install lxml (require for fota generation tool, may require to install with pip2, pip3 and sudo)
pip3 install bsdiff4 (require for fota generation tool, may require to install with pip2, pip3 and sudo)
pip3 install uwsgi
pip3 install waitress
pip3 install gunicorn
pip3 install dotenv

```

If install via proxy, may add "--trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org --proxy="10.220.85.83:9090""
and export http proxy

Example:
```
export http_proxy="http://10.220.85.84:9090"
export https_proxy="http://10.220.85.84:9090"
pip3 install --trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org --proxy="10.220.85.83:9090" flask 
```


# Build server
## Pyinstaller
You may need to install pyinstaller manually
pyinstaller may be blocked by proxy, should manual install
- download zip from https://github.com/pyinstaller/pyinstaller/releases
- extract zip file
- setup http_proxy, https_proxy if need
- Run "python3 setup.py install"

```
$ wget  --no-check-certificate -e use_proxy=yes -e https_proxy=10.220.85.83:9090 https://github.com/pyinstaller/pyinstaller/archive/refs/tags/v4.9.zip
$ unzip v4.9.zip
$ cd pyinstaller-4.9/
$ sudo python3 setup.py install
```

## Build
To build server, run script buildserver.sh
```
$ ./buildserver.sh
```
Build result (deploy folder) shall be located at: .deploy_[yyyymmdd_hhmmss]

Tools locate in "tool" folder shall be copied to deploy folder.
To ignore tools to be copy, add relative path to that tool to file "buildignorecp"
i.e.
```
tool/tbox/sectool/
tool/renesas_tools/dbgsigningtool/
tool/renesas_tools/signingtool/
tool/test_key/
tool/gen_key/
resource/server_cert.pem

# end of file (DON'T REMOVE THIS FILE)
```

# Start server
## Setup db
Add account to mongodb

Run mongo shell:
```
$ mongo
```

Run following mongo command to create account.
Change "pwd" to suitable password

```
use admin
db.createUser(
  {
    user: "vfsigner",
    pwd: "xxx",
    roles: [ { role: "dbOwner", db: "vfsimplesigning" },
            { role: "readWrite", db: "vfsimplesigning" }
    ]
  }
)

use vfsimplesigning
db.createUser(
  {
    user: "vfsigner",
    pwd: "xxx",
    roles: [ { role: "dbOwner", db: "vfsimplesigning" },
            { role: "readWrite", db: "vfsimplesigning" }
    ]
  }
)
```

modify mongodb config to enable authen (/etc/mongodb.conf) (auth=on)
stop and restart mongodb

```
$ mongo admin --eval "db.shutdownServer()"
$ sudo systemctl start mongodb
```

You may need to change owner of monngodb folder
```
$ sudo chown -R mongodb:mongodb /var/lib/mongodb
```

## Start server

Can add loging info of database "vfsimplesigning" to file "dbinfo"
```
DBUSER="<username>"
DBPASS="<password>"
```

You may need to modify "run_server.sh" and "serverconfig" to correct path file

**WARNING:** Be noticed that startserver script shall check if binary serverapp exists (generated when build server)
if "serverapp" exists, run "serverapp", if not, python code "serverapp.py" is executed
You may need to modify "startserver.sh" to force running serverapp.py (remove line APP_CMD_BIN)
if running with serverapp.py, you may need to run buildserver.sh to generate server/ver.py and server/dbg.py

To start server run script "run_server.sh"
```
./run_server.sh
```



## Setup password for database and storage
After starting, access to website, such as https://[IP]:8888, and setup password for db and storage


## Make app to be start automatically

create /etc/systemd/system/vfsimplesigning.service
```
$ sudo nano /etc/systemd/system/vfsimplesigning.service
```
Add following line
Modify 
- "User" to user which run service
- "WorkingDirectory": Full path to working directory of signing server
- "ExecStart": Full path to script to start signing server, normally (WorkingDirectory)/run_server.sh
   Also Open file run_server.sh, also modify "WORKDIR" variable to full path to working directory

```
[Unit]
Description=VinFast Simple Signing Server
After=network.target

[Service]
User=release
Group=www-data
WorkingDirectory=/home/release/vfsimplesigning/
ExecStart=/home/release/vfsimplesigning/run_server.sh

[Install]
WantedBy=multi-user.target
```

Add running user (i.e. release) to group www-data
```
$ sudo usermod -a -G www-data release
```

start service
```
$ sudo systemctl start vfsimplesigning
```

start service at boot

```
$ sudo systemctl enable vfsimplesigning
```


Check service status
```
$ sudo systemctl status vfsimplesigning
```


# Usage
- Check 'http://ip:port/example' to get example for using Restful API

## Sign
- For manual sign using website, go to 'http://ip:port/sign'
- For signing, following information should be added to request:
  * project: tbox, etc.
  * model: vf31, vf32, etc.
  * platform: 9607, etc. (tbox)
  * type: secure, verity, bulk. (tbox)
    * secure: signed with secure boot key
    * verity: signed with verity key
    * bulk: sign zip file with meta data file in zip file
  * sign_id: 
    * "auto"  (base on file name)
    * "sbl1" 
    * "NPRG" 
    * "ENPRG"
    * "prog_nand_firehose"
    * "tz"
    * "devcfg"
    * "cmnlib"
    * "haventkn"
    * "smplap32"
    * "qlaesutl"
    * "qlrsautl"
    * "qlfuseutl"
    * "appsboot"
    * "rpm"
    * "mba"
    * "modem"
    * "mcfg_hw"
    * "mcfg_sw"
    * "rootfs"
    * "oemapp"
    * "legato"
    * "bootimg"


# Deploy on websever
Client --> web gateway (i.e. WSGI) --> App (our app)


# Reference
- pycryptodome: https://pycryptodome.readthedocs.io/en/latest/src/installation.html
- cryptography: https://cryptography.io/en/latest/index.html
- hashlib: https://docs.python.org/3/library/hashlib.html
- pyinstaller: https://github.com/pyinstaller/pyinstaller
- pyinstaller: https://pyinstaller.readthedocs.io/en/stable/usage.html

# FAQ
If you want to install under the Crypto package, replace below pycryptodomex with pycryptodome.
https://pycryptodome.readthedocs.io/en/latest/src/installation.html


# Troubleshooting
## PROXY
Install package via Vingroup proxy may cause issue, you may need to do following steps:
1. Open firefox, access to any website, Firefox shall detect proxy and require login, do login to proxy.
2. For apt, set proxy for apt
```
sudo nano /etc/apt/apt.conf.d/30proxy
==> add following line to 30proxy
Acquire::http::Proxy "http://10.220.85.84:9090";
Acquire::https::Proxy "http://10.220.85.84:9090";
```

3. Export proxy variables
```
$ export http_proxy="http://10.220.85.84:9090"
$ export https_proxy="http://10.220.85.84:9090"
```

4. For pip, add "--trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org --proxy="10.220.85.83:9090" " to pip install
```
$ pip3 install --trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org --proxy="10.220.85.83:9090" flask
```

5. pip package which install via setuptools, may need to add " config --global http.sslVerify false" to pip command and run as sudo

``
$ sudo pip3 install --trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org --proxy="10.220.85.83:9090" dotenv config --global http.sslVerify false
``

## Run bash shell

If you face issue of running bash script, you may need to run with "bash" command
```
$ bash <path to script, i.e. ./buildserver.sh>
$ bash ./buildserver.sh
```

## pyinstaller
If facing error "No module PyInstaller" when build server with pyinstller, you may need to install pyinstaller manually
pyinstaller may be blocked by proxy, should manual install
- download zip from https://github.com/pyinstaller/pyinstaller/releases
- extract zip file
- setup http_proxy, https_proxy if need
- Run "python3 setup.py install"

```
$ wget  --no-check-certificate -e use_proxy=yes -e https_proxy=10.220.85.83:9090 https://github.com/pyinstaller/pyinstaller/archive/refs/tags/v4.9.zip
$ unzip v4.9.zip
$ cd pyinstaller-4.9/
$ sudo python3 setup.py install
```

## List of python module may require:
```
setuptools-rust==0.12.1
altgraph==0.17
aniso8601==8.1.0
apk-parse==1.0.0
asn1crypto==1.4.0
backcall==0.2.0
bsdiff4==1.2.0
certifi==2018.1.18
chardet==3.0.4
click==7.1.2
cmake==3.18.2.post1
colorama==0.4.4
crcmod==1.7
cryptography==2.1.4
cycler==0.10.0
Cython==0.29.22
decorator==4.4.2
dnspython==2.1.0
email-validator==1.1.2
et-xmlfile==1.0.1
Flask==1.1.2
Flask-Login==0.5.0
Flask-Markdown==0.3
flask-mongoengine==1.0.0
Flask-PyMongo==2.3.0
Flask-RESTful==0.3.8
Flask-WTF==0.14.3
future==0.18.2
gunicorn==20.1.0
httplib2==0.9.2
idna==3.1
importlib-metadata==3.7.3
IPy==0.83
ipython==7.16.1
ipython-genutils==0.2.0
itsdangerous==1.1.0
jedi==0.18.0
jsonify==0.5
keyring==10.6.0
keyrings.alt==3.0
kiwisolver==1.3.1
launchpadlib==1.10.6
lazr.restfulclient==0.13.5
lazr.uri==1.0.3
lxml==4.6.2
macaroonbakery==1.1.3
Markdown==3.3.4
mongoengine==0.22.1
natsort==4.0.3
netifaces==0.10.4
networkx==2.5
oauth==1.0.1
olefile==0.45.1
openpyxl==3.0.7
parse==1.18.0
parso==0.8.1
pexpect==4.8.0
pickleshare==0.7.5
Pillow==8.1.0
ply==3.11
prompt-toolkit==3.0.14
protobuf==3.0.0
ptyprocess==0.7.0
pyAesCrypt==5.0.0
pyasn1==0.4.8
pycairo==1.16.2
pycrypto==2.6.1
pycups==1.9.73
pydot==1.4.1
Pygments==2.7.4
pymacaroons==0.13.0
PyNaCl==1.1.2
pyparsing==2.4.7
pyRFC3339==1.0
PySocks==1.7.1
python-dateutil==2.8.1
python-debian==0.1.32
pytz==2020.5
pyxdg==0.25
PyYAML==3.12
reportlab==3.4.0
requests==2.18.4
rsa==4.7
scour==0.36
SecretStorage==2.3.1
semantic-version==2.8.5
simplejson==3.13.2
six==1.15.0
socks==0
ssh-import-id==5.7
toml==0.10.2
traitlets==4.3.3
typing-extensions==3.7.4.3
unidiff==0.5.4
urllib3==1.22
uuid==1.30
uWSGI==2.0.19.1
virtualenv==15.1.0
wadllib==1.3.2
waitress==2.0.0
wcwidth==0.2.5
Werkzeug==1.0.1
WTForms==2.3.3
XlsxWriter==1.3.7
xlwt==1.3.0
zipp==3.4.1
```