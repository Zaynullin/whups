#!/bin/bash
# script updates /etc/whitelist.iptables.cfg file with ip-addresses from  
# whitelist.yclients.cloud DNS-record and reload iptables.whitelist service

[ -z "$(which dig 2>/dev/null)" ] && echo "[ERROR]: no dig executable" 1>&2  && exit 1
[ ! -f "/etc/init.d/iptables.whitelist" ] && echo "[ERROR]: no iptables.whitelist init-script" 1>&2 && exit 1

# DOMAINLIST variable with DNS-records contains needed ip-addresses
DOMAINLIST="office.yclients.tech vpn.yclients.cloud whitelist.yclients.cloud"
# DOMAIN_AUTHORITY_NS  variable for authority DNS-servers, which will be used to get IP lists
DOMAIN_AUTHORITY_NS=""
# DNS_RECURSORS_LIST variable to additional DNS-servers, also used to get IP lists
DNS_RECURSORS_LIST="8.8.8.8 208.67.222.222"
IPLIST=""
WORKDIR="/tmp/workdir.$(basename $0)"

DIG_ADVANCED_PARAMS="+nostats +noquestion -4"

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
    echo "[ERROR]: script is already running" 1>&2
    exit 1
}
###

mlog () {
   echo -e "$(date +%d/%m/%Y:%H:%M:%S) $@" >> ${LOGFILE}
}

e () {
   echo -e "$@" >> ${LOGFILE}
}
###

get_domain_ns () {
    DOMAIN=$1
    [ -z "$DOMAIN" ] && mlog "[ERROR]: Input args are empty in function ${FUNCNAME[@]}" && exit_script

    dig_wrapper $DOMAIN ns

    if [ ! -s ${WORKDIR}/${DOMAIN}.ns*rec ]; then
        PARENT_DOMAIN=$(echo ${DOMAIN} | sed 's,^\w*\.,,g')
        dig_wrapper ${PARENT_DOMAIN} ns
        if [ ! -s ${WORKDIR}/${PARENT_DOMAIN}.ns*rec ]; then
            mlog "[ERROR]: unable to get authority NameServers for domain $DOMAIN"
            exit_script
        else
            DOMAIN_AUTHORITY_NS="$(cat ${WORKDIR}/${PARENT_DOMAIN}.ns*rec)"
        fi
    else
        DOMAIN_AUTHORITY_NS="$(cat ${WORKDIR}/${DOMAIN}.ns*rec)"
    fi
}

dig_wrapper () {
    RECORD=$1
    TYPE=$2
    DNS=$3

    [ -z ${RECORD} ] || [ -z ${TYPE} ] && mlog "[ERROR]: Input args are empty in function ${FUNCNAME[@]}" && exit_script


    #in case not specified DNS-server - use default system settings
    if [ ! -z ${DNS} ]; then
        dig $RECORD -t $TYPE @$DNS $DIG_ADVANCED_PARAMS > "${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out" 2> "${WORKDIR}/${RECORD}.${TYPE}.${DNS}.err"
    else
        DNS="system_default"
        dig $RECORD -t $TYPE $DIG_ADVANCED_PARAMS > "${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out" 2> "${WORKDIR}/${RECORD}.${TYPE}.${DNS}.err"
    fi

    #check dig exit code
    REZ=$?
    if [ $REZ -ne 0 ]; then
        mlog "[ERROR]: Dig finished with code ${REZ} while resolving $DOMAIN"
        e "Dig stdout:\n$(cat ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out)"
        e "Dig stderr:\n$(cat ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.err)"
        exit_script
    fi
    #check response status
    STATUS=$(grep -oP '(?<=status:\s)\w*' ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out)
    if [ "$STATUS" != "NOERROR" ]; then
        mlog "[ERROR]: Dig status ${STATUS} while resolving $RECORD from ${DNS}"
        e "Dig stdout:\n$(cat ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out)"
        e "Dig stderr:\n$(cat ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.err)"
        exit_script
    fi

    if [ `tr '[:upper:]' '[:lower:]' <<< "$TYPE"` == "a" ]; then
        #Get all IP's from DIG response to separate file
        grep -oiP '(?<=IN\sA\s)\d+(\.\d+){3}' ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out | sort > ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.rec
    elif [ `tr '[:upper:]' '[:lower:]' <<< "$TYPE"` == "ns" ]; then
        #Get all NS's from DIG response to separate file
        grep -oiP '(?<=IN\s'ns'\s).*$' ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.out | sort > ${WORKDIR}/${RECORD}.${TYPE}.${DNS}.rec
    fi
}

get_ip_list () {

    for DOMAIN in $DOMAINLIST; do 
        # get records from every authority DNS-server
        unset DOMAIN_AUTHORITY_NS
        get_domain_ns $DOMAIN
        [ -z "$DOMAIN_AUTHORITY_NS" ] && mlog "[ERROR]: empty  domain authority ns list for domain $DOMAIN" && exit_script
        for IT_NS in $DOMAIN_AUTHORITY_NS; do
            dig_wrapper $DOMAIN a $IT_NS
        done
        # also get records from every additional DNS-server
        for IT_RECURSOR in $DNS_RECURSORS_LIST; do
            dig_wrapper $DOMAIN a $IT_RECURSOR
        done


        # check received data, all received ip lists must be the same
        md5sum ${WORKDIR}/${DOMAIN}.[Aa].*.rec > ${WORKDIR}/${DOMAIN}.md5check
        CHECK=$(awk '{print $1}' < ${WORKDIR}/${DOMAIN}.md5check | sort -u | wc -l)
        if [ $CHECK -ne 1 ]; then
                mlog "[ERROR]: $DOMAIN did not pass consistency check. MD5Hash check\n$(cat ${WORKDIR}/${DOMAIN}.md5check | sed 's,'${WORKDIR}'/'${DOMAIN}'\.[Aa]\.\(.*\)\.rec$,\1,g')\n"
                # SUM1 contains md5hash of most frequent ips lists - consider it as correct answer
                SUM1=$(awk '{print $1}' < ${WORKDIR}/${DOMAIN}.md5check | sort | uniq -c | sort -rn | head -n 1 | awk '{print $2}')
                SUM2=$(awk '{print $1}' < ${WORKDIR}/${DOMAIN}.md5check | sort | uniq -c | sort -n | head -n 1 | awk '{print $2}')

                MOST_FREQ_REQ_OUTPUT=$(grep $SUM1 ${WORKDIR}/${DOMAIN}.md5check  | head -n 1 | awk '{print $2}' | sed 's,rec$,out,g')
                e "MOST FREQUENT ANSWER IS FROM: $(echo $MOST_FREQ_REQ_OUTPUT | sed 's,'${WORKDIR}'/'${DOMAIN}'\.[Aa]\.\(.*\)\.out$,\1,g')"
                e "$(cat $MOST_FREQ_REQ_OUTPUT)\n"

                SUMS2=$(grep -v $SUM1 ${WORKDIR}/${DOMAIN}.md5check | awk '{print $1}' | sort -u)

                for SUM2 in $SUMS2; do
                    LESS_FREQ_REQ_OUTPUT=$(grep $SUM2 ${WORKDIR}/${DOMAIN}.md5check  | head -n 1 | awk '{print $2}' | sed 's,rec$,out,g')
                    e "LESS FREQUENT ANSWER ($SUM2) FROM: $(echo $LESS_FREQ_REQ_OUTPUT | sed 's,'${WORKDIR}'/'${DOMAIN}'\.[Aa]\.\(.*\)\.out$,\1,g')"
                    e "$(cat $LESS_FREQ_REQ_OUTPUT)\n"
                done
                exit_script
        else
            mlog "[OK]: Domain '$DOMAIN' passed consistency check"
        fi
    done

}

combine_iplist () {
    PRE_IPLIST=""
    for DOMAIN in $DOMAINLIST; do
        PRE_IPLIST+=" $(cat $(/bin/ls ${WORKDIR}/${DOMAIN}.[Aa].*.rec| head -n1) | sort -n |uniq)"
    done
    IPLIST=$(echo "${PRE_IPLIST}" | tr ' ' '\n' | sort | uniq | grep -v '^$')
}

validate_ip () {
    RECORD_TO_CHECK=$1
    [[ ${RECORD_TO_CHECK} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

validate () {
    LINE_NO=`echo -n "$IPLIST" | wc -l`
    if [ $LINE_NO -eq 0 ]; then
            mlog "[ERROR]: Got empty IP list"
            exit_script
    fi
    COUNT=0
    for i in $IPLIST; do
        if ! validate_ip $i; then
            ((COUNT++))
            mlog "[ERROR]: $i fail IP-check"
        fi
    done
    if [ $COUNT -gt 0 ]; then
            mlog "[ERROR]: some IPs fails the IP-check. See logs for details"
            exit_script
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

cleanup

[ ! -d "${WORKDIR}" ] && mkdir -p "${WORKDIR}"

mlog "Starting whitelist IPs processing"

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
    mlog "Current IPs list equals to previous IPs list. Skip updating"
fi
