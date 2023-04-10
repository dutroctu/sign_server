#!/bin/sh

HOME=`pwd`
INPUT_PASS=0
storagepassword=
dbpassword=
KEY="${HOME}/keyinfo"
APP_CMD_PY="python3 app.py"
APP_CMD_BIN="${HOME}/app"
APP_CMD=
CERT="${HOME}/server_cert.pem"
CERT_KEY="${HOME}/server_key.pem"
TLS=1
storagepassword=""
dbpassword=""
if test -f "${KEY}"; then
    source ${KEY}
fi

if [ -f ${APP_CMD_BIN} ]; then
APP_CMD=${APP_CMD_BIN}
else
APP_CMD=${APP_CMD_PY}
fi

if [ -z "$storagepassword" ] ;
then
    read -s -p "Storage password: " storagepassword
    echo -e "\n"
fi

if [ -z "$dbpassword" ] ;
then
    read -s -p "Database password: " dbpassword
    echo -e "\n"
fi

if [ -z "$storagepassword" ] || [ -z "$dbpassword" ] ;
then
    echo -e "NO storage nor db password is set"
else
    CERT_PARAM=
    if [ $TLS == 1 ]; then
        if [ ! -f ${CERT_KEY} ]; then
            ip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`
            openssl req -x509 -newkey rsa:4096 -nodes -out ${CERT} -keyout ${CERT_KEY} -days 7300 -subj /C=VN/ST=HP/L=HP/OU="VinFast Signing"/O="VinFast"/CN=$ip
        fi
        CERT_PARAM="--cert ${CERT} --key ${CERT_KEY}"
    fi
    DB_PARAM=
    if [ ! -z "$dbpassword" ] ; then
        DB_PARAM="-d ${dbpassword}"
    fi
    STORAGE_PARAM=
    if [ ! -z "$storagepassword" ] ; then
        STORAGE_PARAM="-f ${storagepassword}"
    fi
    # eval ${APP_CMD} -d ${dbpassword} -f ${storagepassword} --cert ${CERT} --key ${CERT_KEY}
    # eval ${APP_CMD} -d ${dbpassword} -f ${storagepassword}
    # eval ${APP_CMD}
    eval ${APP_CMD} ${STORAGE_PARAM} ${DB_PARAM}  ${CERT_PARAM}

fi