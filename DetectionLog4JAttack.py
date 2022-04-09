#!/usr/bin/env python3

import sys
import argparse
import os
import re
import json
import pandas as pd
import logging as log
from arielapiclient import APIClient
from socket import *
from RestApiClient import RestApiClient
from datetime import datetime, timedelta
from jndi_deobfuscate.jndi_deobfuscate import process_line

api_client = RestApiClient()
server_ip = api_client.server_ip

def send_msg_to_socket(str_msg, dest=server_ip, port=514):
    import time
    sock = socket(AF_INET, SOCK_DGRAM)
    msg=str_msg.encode()
    i = sock.sendto(msg, (dest, port))
    sock.close()

def create_log_msg(sourceip, destinationip, contactedip, contacttime):
    from time import strftime
    msg = ''
    msg = strftime('%b %d %H:%M:%S') + ' ExternalOffense ' +\
        'type=log4j|source=' + sourceip + '|dest=' + destinationip + '|contacted=' + contactedip + \
        '|contacttime=' + contacttime + '|'
    return msg

def write_file(string, filename='last_run.txt'):
    try:
        file = open(filename, 'w')
        file.write(string)
        file.close()
    except:
        log.warning("File writing not available")
    return

def read_file(filename='last_run.txt'):
    file_path = os.path.dirname(os.path.abspath(__file__))
    file = open(file_path+"/"+filename, 'r')
    line = file.readlines()[0]
    if(line[-1] == '\n' or line [-1] == '\r'):
        line = line[:-1]
    date_time_obj = datetime.strptime(line, '%Y-%m-%d %H:%M')
    return date_time_obj

def name_resolve(host_or_ip, lista):
    import socket
    import re
    if host_or_ip is None:
        return None    
    p = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if(p.match(host_or_ip)):
        lista.append([host_or_ip, host_or_ip])
        return host_or_ip
    else:
        try:
            p = re.compile('(?i)^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$')
            if(p.match(host_or_ip)):# valid domains
                for ip in socket.gethostbyname_ex(host_or_ip)[2]:
                    lista.append([host_or_ip, ip])
                return socket.gethostbyname_ex(host_or_ip)
            else:
                return None
        except:
            return None    

def get_qradar_time():
    response = api_client.call_api('system/about', 'GET')
    response_json = json.loads(response.read().decode('utf-8'))
    dt=response.getheader('Date')
    date_time_obj = datetime.strptime(dt, '%a, %d %b %Y %H:%M:%S %Z')
    return(date_time_obj)

def get_interval_for_attempt(datetime):
    datetime = datetime.replace(minute=0, second=0)
    start = datetime - timedelta(hours=1, minutes=5)
    string = ' START ' + start.strftime('\'%Y-%m-%d %H:%M\'') + ' STOP ' + datetime.strftime('\'%Y-%m-%d %H:%M\'')
    return string

def get_interval_for_success(datetime):
    datetime = datetime.replace(minute=0, second=0)
    start = datetime - timedelta(hours=1)
    string = ' START ' + start.strftime('\'%Y-%m-%d %H:%M\'') + ' STOP ' + datetime.strftime('\'%Y-%m-%d %H:%M\'')
    return string

def get_times_to_do(filename='last_run.txt'):
    qradar_time = get_qradar_time()
    try:
        last_time_done = read_file(filename)
    except:
        log.warning("Problem reading the file, still running")
        t=list()
        t.append(qradar_time)
        return t
    time_range = pd.date_range(last_time_done, qradar_time, freq='H')
    qradar_time = qradar_time.replace(minute=0, second=0)
    if( len(time_range)>1 and len(time_range)<=4 ):
        return time_range[-len(time_range)+1:]
    elif( len(time_range)>4 ):
        return time_range[-3:]
    elif( len(time_range)==1 ):
        print("Execution already carried out for this time")
        exit(0)

def get_hostname_from_jndi(pattern, jndi_string):
    if jndi_string is None or pattern is None:
        return None
    res = re.search(pattern, jndi_string)
    if res is not None:
        return res.group(1)
    else:
        return None    

def query(sql):
    log.info(sql)
    api_client = APIClient()
    query_expression = sql
    response = api_client.create_search(query_expression)
    log.info("STATUS: " + str(response.code))
    if response.code<200 or response.code >299 :
        log.error("Query execution error.")
        return None
    response_json = json.loads(response.read().decode('utf-8')) #dict
    search_id = response_json['search_id'] #get search id to retrieve aql results
    response = api_client.get_search(search_id) #get results
    error = False
    while (response_json['status'] != 'COMPLETED') and not error:
        if (response_json['status'] == 'EXECUTE') | \
                (response_json['status'] == 'SORTING') | \
                (response_json['status'] == 'WAIT'):
            response = api_client.get_search(search_id)
            response_json = json.loads(response.read().decode('utf-8'))
        else:
            log.error(response_json['status'])
            error = True
    if(error):
        log.error("QUERY ERROR")
    response = api_client.get_search_results(
        search_id, 'application/json')
    body = response.read().decode('utf-8')
    body_json = json.loads(body)
    json_res = body_json['events']
    df = pd.DataFrame.from_dict(json_res, orient='columns')
    return df

def create_ip_table_from_hostname(host_list):
    unique_host_list = []
    ip_table = []
    for h in host_list:
        if h not in unique_host_list:
            name_resolve(h, ip_table)
        unique_host_list.append(h)
    return pd.DataFrame(ip_table, columns=['malicioushost', 'maliciousip'])

def get_malicious_hostlist_from_payload(payload_list):
    pattern = "\$(?:\{|%7B)jndi:(?:ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):\/\/(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+).*?}"
    malicioushost = []
    for payload in payload_list:
        jndi_string = process_line(payload, print_output=False)
        malicioushost.append(get_hostname_from_jndi(pattern, jndi_string))
    return malicioushost

def get_ip_string_from_ip_list(ip_list):
    ip_list = list(dict.fromkeys(ip_list))
    string_dest = '('
    for ip in ip_list:
        string_dest += "'" + ip + "',"
    if len(string_dest)!= 1 :
        string_dest = string_dest[:-1]
        string_dest += ")"
        return string_dest
    else:
        log.info("No ip found")
        return
    

def main(time):
    pd.set_option('display.max_columns', 500)
    pd.set_option('display.width', 1000)
    qradar_time = time
    if(time is None):
        time_q1 = args.t
        time_q2 = args.t
    else:
        time_q1 = get_interval_for_attempt(qradar_time)
        time_q2 = get_interval_for_success(qradar_time)

    r2l = ""
    if args.r2l :
        r2l = " eventdirection='R2L' and"
        
    condition = "and UTF8(payload) IMATCHES '.*(\$|%24)(\{|%7B).*(:|%3A).*(}|%7D).*' "
    if args.ext:
        condition = "and DETECT::LOG4J(UTF8(payload)) "
    dest = query("select starttime as time, DATEFORMAT(startTime, 'dd/MM/yyyy HH:mm:ss') AS StartTime,\
        sourceip as hackerip, UTF8(payload) as maliciouspayload from events\
        where" + r2l + " devicetype != 105 and devicetype != 18 " + condition + time_q1)
    if dest is None:
        return
    
    print("Query 1/2 completed")
    if(dest.empty):
        print("No attempt detected!")
        return
    
    malicioushost = get_malicious_hostlist_from_payload(dest['maliciouspayload'])
    dest['malicioushost'] = malicioushost
    dest = dest.drop(columns=['maliciouspayload'])
    
    ip_table = create_ip_table_from_hostname(malicioushost)
    dest = dest.join(ip_table.set_index('malicioushost'), on='malicioushost', rsuffix='_')
    if args.v:
        print(dest)
    string_dest = get_ip_string_from_ip_list(ip_table['maliciousip'])
    if string_dest is None:
        print("No IP found!")
        return

    if args.v:
        print('_'*90)
    res = query("select starttime as time, DATEFORMAT(startTime, 'dd/MM/yyyy HH:mm:ss') AS StartTime, sourceip, destinationip, destinationport from events\
                where eventdirection='L2R' and\
                CONCAT('', destinationip) in " + string_dest + " " + time_q2)
    if res is None:
        return
    
    print("Query 2/2 completata")
    
    if(res.empty):
        print("No attack found!")
        return
    if args.v:
        print(res)
        print('*'*80)

    log4j = dest.join(res.set_index('destinationip'), on='maliciousip', rsuffix='_')
    q = 'abs(time-time_)<=300'
    if args.ms!=None:
        q = 'abs(time-time_)<=' + str(args.ms)
    log4j = log4j.query(q).drop(['time_', 'time'], axis=1)
    if ((not args.o) or args.v) and not log4j.empty:
        print("Offense list:")
        print(log4j)
        print('*'*80)
    temp  = log4j.to_dict()
    c = 0
    for j in temp['StartTime']:
        if args.o:
            send_msg_to_socket(create_log_msg(temp['hackerip'][j],temp['sourceip'][j], temp['maliciousip'][j], temp['StartTime'][j] ))
        c =c+1
    print("Detected " + str(c) + " offense!")

if __name__ == "__main__":
    handlers = []
    handlers.append(log.StreamHandler(sys.stdout))
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', metavar='"time"', type=ascii, help='"last n hours|minutes|seconds"|"start \'YYYY-MM-DD hh:mm\' stop \'YYYY-MM-DD hh:mm\'" (where n is integer)')
    parser.add_argument('-ms', metavar='millis', type=int, help='(default=300ms) max milliseconds to evaluate the correlation between first attempt and connection to malicious destination')
    parser.add_argument('-o', action='store_false', help='shows offense on console and NOT send offense to QRadar')
    parser.add_argument('-r2l', action='store_true', help='(R2L) if present, the query 1 considers only Remote To Local log.')
    parser.add_argument('-ext', action='store_true', help='if present, the query 1 uses DETECT::LOG4J extension on payload to detect attempt')
    parser.add_argument('-v', action='store_true', help='print detailed operations, useful for debug')
    args = parser.parse_args()
    if(args.v):
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO, handlers=handlers)
    if(args.t!=None):
        args.t = args.t[1:-1]
        if(re.match("(?i)^last \d+ (?:hours|minutes|seconds)$|(?:^start '\d{4}(?:-\d{2}){2} \d{2}:\d{2}' stop '\d{4}(?:-\d{2}){2} \d{2}:\d{2}')$", args.t) is None):
            print(str(args.t))
            print("Format -t not correct. Example: \"last 5 hours\" or \"start '2022-03-10 14:55' stop '2022-03-10 16:00'\" (also write the quotes) ")
            exit()
        main(None)
    else:
        for time in get_times_to_do():
            print("##START\tTime: ", time,"##")
            main(time)
            write_file(time.replace(minute=0, second=0).strftime('%Y-%m-%d %H:%M'))
            print("##END##\n")
