#!/bin/bash
# script update /etc/whitelist.iptables.cfg file with ip-addresses from
# whitelist.yclients.cloud DNS-record and reload iptables.whitelist service

[ -z "$(which dig 2>/dev/null)" ] && echo "ERROR: no dig executable" 1>&2  && exit 1
[ ! -f "/etc/init.d/iptables.whitelist" ] && echo "ERROR: no iptables.whitelist init-script" 1>&2 && exit 1

#DOMAINLIST="whitelist.yclients.cloud"
# DOMAINLIST variable with DNS-records contains needed ip-addresses
DOMAINLIST="office.yclients.tech vpn.yclients.cloud whitelist.yclients.cloud"
# ZONE variable contains main DNS-zone - this zone will be used to get main DNS-servers (MAIN_DNS variable)
ZONE="yclients.cloud"
# MAIN_DNS  variable for authority DNS-servers, which will be used to get IP lists
MAIN_DNS=""
# ADDITIONAL_DNS variable to additional DNS-servers, also used to get IP lists
ADDITIONAL_DNS="8.8.8.8 208.67.222.222"
IPLIST=""
WORKDIR="/tmp/workdir.$(basename $0)"

if [ -f "/srv/southbridge/etc/moresalonov.update_whitelist.conf.dist" ]; then
    . "/srv/southbridge/etc/moresalonov.update_whitelist.conf.dist"
    if [ -f "/srv/southbridge/etc/moresalonov.update_whitelist.conf" ]; then
        . "/srv/southbridge/etc/moresalonov.update_whitelist.conf"
    fi
fi

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

IP_CURRENT_LIST=/etc/whitelist.iptables.cfg
IP_NEW_LIST=/tmp/iptables.new.whitelist.cfg

LOGFILE=/var/log/$(basename $0).log

LOCK_FILE=/tmp/.$(basename $0).lock
### DOUBLE RUN PROTECTION
exec 200>${LOCK_FILE}

flock -n 200 || {
    echo "ERROR. Already running" 1>&2
    exit 1
}
###

mlog () {
   echo -e "$(date +%d/%m/%Y:%H:%M:%S) $@" >> ${LOGFILE}
}

###

[ ! -d "${WORKDIR}" ] && mkdir -p "${WORKDIR}"


get_main_dns () {
    unset MAIN_DNS
    MAIN_DNS=($(dig ${ZONE} ns +short  | sort | grep -vE '^(;|$)'))
    DIG_RETURN_CODE=$?
    [ ${DIG_RETURN_CODE} -ne 0 ] && {
        mlog "Dig return code ${DIG_RETURN_CODE} while resolving $ZONE NS list"
        exit_script
    }
    [ ${#MAIN_DNS[@]} -eq 0 ] && mlog "ERROR: got empty main DNS list" && exit_script

    mlog "Got main dns list: ${MAIN_DNS[@]}"
}

get_ip_list () {

    for DOMAIN in $DOMAINLIST; do
        # get records from every authority DNS-server
        for IT_MAIN_DNS in ${MAIN_DNS[@]}; do
            dig $DOMAIN @${IT_MAIN_DNS} +short | sort | grep -vE '^([^0-9]|$)' > "${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.out" 2>"${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.err"
            DIG_RETURN_CODE=$?
            [ ${DIG_RETURN_CODE} -ne 0 ] && {
                mlog "Dig return code ${DIG_RETURN_CODE} while resolving $DOMAIN from ${IT_MAIN_DNS}"
                mlog "Dig stdout: $(cat ${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.out)"
                mlog "Dig stderr: $(cat ${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.err)"
                exit_script
            }
            LINES_COUNT=$(wc -l ${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.out | awk '{print $1}')
            [ $LINES_COUNT -eq 0 ] && {
                mlog "Got empty response while resolving $DOMAIN from ${IT_MAIN_DNS}"
                mlog "Dig stdout: $(cat ${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.out)"
                mlog "Dig stderr: $(cat ${WORKDIR}/${DOMAIN}.from.${IT_MAIN_DNS}.err)"
                exit_script
            }
        done
        # also get records from every additional DNS-server
        for ADD_DNS in $ADDITIONAL_DNS; do
            dig $DOMAIN @${ADD_DNS} +short | sort | grep -vE '^([^0-9]|$)' > "${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.out" 2>"${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.err"
            [ ${DIG_RETURN_CODE} -ne 0 ] && {
                mlog "Dig return code ${DIG_RETURN_CODE} while resolving $DOMAIN from ${ADD_DNS}"
                mlog "Dig stdout: $(cat ${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.out)"
                mlog "Dig stderr: $(cat ${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.err)"
                exit_script
            }
            LINES_COUNT=$(wc -l ${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.out | awk '{print $1}')
            [ $LINES_COUNT -eq 0 ] && {
                mlog "Got empty response while resolving $DOMAIN from ${ADD_DNS}"
                mlog "Dig stdout: $(cat ${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.out)"
                mlog "Dig stderr: $(cat ${WORKDIR}/${DOMAIN}.from.${ADD_DNS}.err)"
                exit_script
                }
        done


        # check received data
        CHECK=$(md5sum ${WORKDIR}/${DOMAIN}.from.*.out | awk '{print $1}' | sort | uniq -c | wc -l)
        if [ $CHECK -ne 1 ]; then
            mlog "Error checking recieved data for $DOMAIN. Recived data below"
            for i in ${WORKDIR}/${DOMAIN}.from.*; do
                mlog "$i:\n$(cat $i)"
            done
            exit_script
        else
            mlog "Domain: '$DOMAIN' passed consistency check"
        fi
    done

}

combine_iplist () {
    IPLIST="$(cat ${WORKDIR}/${DOMAIN}.from.${MAIN_DNS[0]}.out| sort -n)"
}

validate_ip () {
        RECORD_TO_CHECK=$1
        if [[ ${RECORD_TO_CHECK} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                true
        else
                false
        fi
}

validate () {
        LINE_NO=`echo -n "$IPLIST" | wc -l`
        COUNT=0
        for i in $IPLIST; do
                if ! validate_ip $i; then
                ((COUNT++))
        echo "ERROR: $i is not IP"
        fi
        done
        if [ $COUNT -gt 0 ]; then
                exit_script
        else
                if [ $LINE_NO -gt 0 ]; then
                        true
                else
                        mlog "Got empty IP list"
                        exit_script
                fi
        fi
}

cleanup () {
    [ -d  "${WORKDIR}" ] && rm -rf "${WORKDIR}"
}

exit_script (){
    cleanup
    mlog "Exiting"
    exit 1
}

mlog "\n==============================\nStart update whitelist process\n=============================="

get_main_dns

get_ip_list

combine_iplist

validate

echo "$IPLIST" > ${IP_NEW_LIST}

cleanup

CUR_LIST_CHECK="$(/usr/bin/md5sum ${IP_CURRENT_LIST} 2>/dev/null| awk '{print $1}')"
NEW_LIST_CHECK="$(/usr/bin/md5sum ${IP_NEW_LIST} 2>/dev/null| awk '{print $1}')"

if [ "$CUR_LIST_CHECK" != "$NEW_LIST_CHECK" ]; then
        mlog "Updating iptables whitelist"
        mlog "New iplist:\n$(cat ${IP_NEW_LIST})"
        mlog "Old iplist:\n$(cat ${IP_CURRENT_LIST})"
        mlog "Diff: $(diff ${IP_CURRENT_LIST} ${IP_NEW_LIST})"
        cp -pf ${IP_NEW_LIST} ${IP_CURRENT_LIST}
        mlog "$(/etc/init.d/iptables.whitelist reload 2>&1)"
        mlog "Update complete"
else
    mlog "New iplist equal to old iplist. Skip update"
fi
