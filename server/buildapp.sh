#!/bin/sh

HOME=`pwd`
APP_NAME="app"
BUILD_DIR=".build"
DIST_DIR=".dist"
DIST_APP="${DIST_DIR}/${APP_NAME}"
TARGET_APP="${HOME}/${APP_NAME}"
DEPLOY="${HOME}/.deploy"
TEMPLATE="${HOME}/templates"
STATIC="${HOME}/static"
START_APP_SCRIPT="${HOME}/start_app.sh"
CERT="${HOME}/server_cert.pem"
CERT_KEY="${HOME}/server_key.pem"
KEY="${HOME}/keyinfo"
# https://pyinstaller.readthedocs.io/en/stable/usage.html
echo "rm ${DIST_APP}"
rm ${DIST_APP}
rm ${TARGET_APP}

if [ -d $DEPLOY ]; then
    rm -rfv  $DEPLOY
fi
mkdir -p $DEPLOY

echo "pyinstaller --distpath ${DIST_DIR}  --workpath ${BUILD_DIR} -s -F --add-data \"templates:templates\" --add-data \"static:static\" app.py"
pyinstaller --distpath ${DIST_DIR}  --workpath ${BUILD_DIR} -s -F --add-data "templates:templates" --add-data "static:static" app.py
if test -f "$DIST_APP"; then
    echo "cp ${DIST_APP} ${TARGET_APP}"
    cp ${DIST_APP} ${DEPLOY}

    # echo "cp -r ${TEMPLATE} ${DEPLOY}"
    # cp -rfv ${TEMPLATE} ${DEPLOY}
    
    # echo "cp -r ${STATIC} ${DEPLOY}"
    # cp -rfv ${STATIC} ${DEPLOY}

    if [ -f ${START_APP_SCRIPT} ]; then
        echo "cp -r ${START_APP_SCRIPT} ${DEPLOY}"
        cp -rfv ${START_APP_SCRIPT} ${DEPLOY}
    fi
    if [ -f ${CERT} ]; then
        echo "cp -r ${CERT} ${DEPLOY}"
        cp -rfv ${CERT} ${DEPLOY}
    fi
    if [ -f ${CERT_KEY} ]; then
        echo "cp -r ${CERT_KEY} ${DEPLOY}"
        cp -rfv ${CERT_KEY} ${DEPLOY}
    fi
    if [ -f ${KEY} ]; then
        echo "cp -r ${KEY} ${DEPLOY}"
        cp -rfv ${KEY} ${DEPLOY}
    fi
else
    echo "FAILED"
fi