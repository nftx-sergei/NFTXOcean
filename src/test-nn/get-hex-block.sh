#!/usr/bin/env bash
# (c) Decker 2022

# --------------------------------------------------------------------------
function init_colors() {
    RESET="\033[0m"
    BLACK="\033[30m"
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BLUE="\033[34m"
    MAGENTA="\033[35m"
    CYAN="\033[36m"
    WHITE="\033[37m"
    BRIGHT="\033[1m"
    DARKGREY="\033[90m"
}

# --------------------------------------------------------------------------
function log_print() {
   datetime=$(date '+%Y-%m-%d %H:%M:%S')
   echo -e [$datetime] $1 | tee --append $LOGFILE
   
}
# --------------------------------------------------------------------------
# https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html

function checkconfig()
{
	if ! grep -qs '^rpcpassword=' "${KOMODOD_CONFIGFILE}" ; then
		log_print "Parsing: ${KOMODOD_CONFIGFILE} - ${RED}FAILED${RESET}"
		return 1
    fi
    if ! grep -qs '^rpcuser=' "${KOMODOD_CONFIGFILE}" ; then
		log_print "Parsing: ${KOMODOD_CONFIGFILE} - ${RED}FAILED${RESET}"
		return 1
    fi

    grep -qs '^rpcpassword=' "${KOMODOD_CONFIGFILE}"
    KOMODOD_RPCPASSWORD=$(grep -s '^rpcpassword=' "${KOMODOD_CONFIGFILE}")
    KOMODOD_RPCPASSWORD=${KOMODOD_RPCPASSWORD/rpcpassword=/}
    KOMODOD_RPCPASSWORD=$(echo $KOMODOD_RPCPASSWORD | cut -d " " -f 1)
    
    grep -qs '^rpcuser=' "${KOMODOD_CONFIGFILE}"
    KOMODOD_RPCUSER=$(grep -s '^rpcuser=' "${KOMODOD_CONFIGFILE}")
    KOMODOD_RPCUSER=${KOMODOD_RPCUSER/rpcuser=/}
    KOMODOD_RPCUSER=$(echo $KOMODOD_RPCUSER | cut -d " " -f 1)

    if ! grep -qs '^rpcport=' "${KOMODOD_CONFIGFILE}" ; then
		KOMODO_RPCPORT=7771
    else
        KOMODO_RPCPORT=$(grep -s '^rpcport=' "${KOMODOD_CONFIGFILE}")
        KOMODO_RPCPORT=${KOMODO_RPCPORT/rpcport=/}
    fi
    
    log_print "Parsing RPC credentials: ${KOMODOD_CONFIGFILE} - ${GREEN}OK${RESET}"
    
}

KOMODOD_DEFAULT_DATADIR=${KOMODOD_DEFAULT_DATADIR:-"$HOME/.komodo"}
KOMODOD_CONFIGFILE=${KOMODOD_CONFIGFILE:-"$KOMODOD_DEFAULT_DATADIR/komodo.conf"}
KOMODOD_RPCHOST=127.0.0.1

# https://stackoverflow.com/questions/4774054/reliable-way-for-a-bash-script-to-get-the-full-path-to-itself
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
LOGFILE="${SCRIPTPATH}/${0##*/}.log"
BLOCKFILE=blocks.hex

init_colors
checkconfig

rm ${SCRIPTPATH}/${BLOCKFILE}
touch ${SCRIPTPATH}/${BLOCKFILE}

KOMODO_RPCPORT=17771
for ht in $(seq 1 137); do 
    res=$(curl -s --user "${KOMODOD_RPCUSER}:${KOMODOD_RPCPASSWORD}" --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblock", "params": ["'${ht}'", 0] }' -H 'content-type: text/plain;' http://${KOMODOD_RPCHOST}:${KOMODO_RPCPORT} | jq .)
    if [ -z "$(echo $res | jq .result)" ] || [ "$(echo $res | jq .result)" == "null" ]; then
        log_print "Fetch ht.${ht} - ${RED}FAIL${RESET}"
        log_print "${DARKGREY}""$(echo $res)""${RESET}"
        exit 1
    fi
    echo $res | jq -r .result >> ${SCRIPTPATH}/${BLOCKFILE}
    log_print "Fetch ht.${ht} - ${GREEN}OK${RESET}"
done