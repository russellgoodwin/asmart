#!/usr/bin/env python

## Author: Russell Goodwin, Illumio inc. v0.0.1 - 18th March 2024.
## Python 3.12 script, requiring the asprequests wrapper


import asprequests
import json
import concurrent.futures
import datetime
import sqlite3 as db
from itertools import zip_longest
import csv
import configparser
import sys

MAX_THREADS = 10

def main():

    asprequests.checkconfig()
    configfile = 'asmart.conf'
    config = getconfig(configfile)
    orgID = asprequests.getorg()
    config['orgID'] = orgID

    cursor, con = createdb(orgID)
    
    #wlhref = '/orgs/3997789/workloads/0028a280-942f-49f2-bbee-adf5cc53aa4d'
    #wllist = [wlhref]

    wllist, workloads = getworkloads(orgID)

    builddb(config, cursor, con, workloads, wllist)

    analysedb(config, cursor, con, wllist)


def builddb(config, cursor, con, workloads, wllist):

    # Build the various DB tables from API data
    createwldb(cursor, workloads)
    createportdb(config, cursor, con, workloads)
    createtrafficdb(cursor, con)
    populatetraffic(config, cursor, con, wllist)


def analysedb(config, cursor, con, wllist):
    scoreports(config, cursor, con)
    scorewls(config, cursor, con, wllist)


def grouper(iterable, n, *, incomplete='fill', fillvalue=None):
    # Module copied from more-iter-tools to support multithreading for API calls
    iterators = [iter(iterable)] * n
    match incomplete:
        case 'fill':
            return zip_longest(*iterators, fillvalue=fillvalue)
        case 'strict':
            return zip(*iterators, strict=True)
        case 'ignore':
            return zip(*iterators)
        case _:
            raise ValueError('Expected fill, strict, or ignore')


def getconfig(configfile):
    with open(configfile) as conf:
        config = json.load(conf)

    return config


def createdb(orgID):
    # Open an existing SQLite DB, or create one if it doesn't exist.
    # The DB will contain workload details and stats, as well as traffic data
    try:
        con = db.connect('file:{0}.db?mode=rw'.format(orgID), uri=True)
        print("Opened existing DB: {0}.db".format(orgID))
    except:
        con = db.connect("{0}.db".format(orgID))
        print("Created DB: {0}.db".format(orgID))
    cursor = con.cursor()

    return cursor, con


def getworkloads(orgID):
    
    wllist = []
    
    ## Get workloads.
    url = "/orgs/{0}/workloads?representation=workload_labels&managed=true".format(orgID)
    
    workloads = asprequests.call(url)['response']

    if len(workloads) == 500:
        print("Found 500+ Workloads, using Async fetch")
        workloads = asprequests.bulk(url)['response']
        
    print("Collecting detail for {0} matching workloads".format(len(workloads)))

    wldetail = []
    
    def thread_workloads(workloads):
        for workload in workloads:
            
            wllist.append(workload['href'])

            retries = 0
            while retries < 3:
                wl = asprequests.call(workload['href'])
                if wl['HTTPcode'] == 200:
                    break
                else:
                    retries += 1
            if retries > 2:
                print("Fetch of workload '{0}' failed after 3 retries".format(workload['href']).splitr('/')[-1])

            
            wldetail.append(wl)

    
    executor = concurrent.futures.ThreadPoolExecutor(10)
    futures = [executor.submit(thread_workloads, group)
                for group in grouper(workloads, 5)]
    concurrent.futures.wait(futures)

    return wllist, wldetail
    

def buildtrafficquery(queryhours, href):
    # Constructs a traffic query with the destination of a specific workload and a defined query interval from the .conf file
    querystart = ((datetime.datetime.now() - datetime.timedelta(hours=queryhours)).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    queryend = (datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z"))

    destquery = {"boundary_decisions":[],"destinations":{"exclude":[],"include":[[{"workload":{"href":href}}]]},"end_date":queryend,
             "exclude_workloads_from_ip_list_query":True,"max_results":100000,"policy_decisions":[],"query_name":"Dest Traffic Query for Exposure tool",
             "services":{"exclude":[],"include":[]},"sources":{"exclude":[],"include":[[]]},"sources_destinations_query_op":"and","start_date":querystart}
    
    sourcequery = {"boundary_decisions":[],"destinations":{"exclude":[],"include":[[]]},"end_date":queryend,
             "exclude_workloads_from_ip_list_query":True,"max_results":100000,"policy_decisions":[],"query_name":"Source Traffic Query for Exposure tool",
             "services":{"exclude":[],"include":[]},"sources":{"exclude":[],"include":[[{"workload":{"href":href}}]]},"sources_destinations_query_op":"and","start_date":querystart}

    return destquery, sourcequery


def trafficquery(config, wl):
    # Run a traffic query for all traffic destined and sourced to/from a given WL href for the configured time interval
    print("Running traffic query for Workload: {}".format(wl.rsplit('/')[-1]))
    href = "/orgs/{0}/traffic_flows/async_queries".format(config['orgID'])
    destquery, sourcequery = buildtrafficquery(config['queryhours'], wl)

    counter = 0
    success = 0
    while counter < 3 and success < 2:
        success = 0
        try:
            destresults = asprequests.traffic(url=href,payload=destquery)
            if destresults['HTTPcode'] == 200:
                success += 1
        except:
            destresults = []
        try:
            sourceresults = asprequests.traffic(url=href,payload=sourcequery)
            if sourceresults['HTTPcode'] == 200:
                success += 1
        except:
            sourceresults = []

        counter += 1

    if counter == 1:
        pass
    elif counter >= 2 and counter <= 3:
        print("Traffic flows collected in {0} tries".format(counter))
    else:
        print("Traffic collection failed for {0} after {1} tries".format(wl,counter))

    return destresults, sourceresults


def createwldb(cursor, wldetail):

    cursor.execute("DROP TABLE IF EXISTS workloads")

    query = "CREATE TABLE IF NOT EXISTS workloads (uuid char(30) PRIMARY KEY, hostname text, loc text, env text, app text, role text, href text, state text,\
             policy integer, flows integer, process_count integer, exp_src_peers integer, exp_score integer, real_src_peers integer, real_dst_peers integer, \
             total_src_flows integer, total_dst_flows integer, total_ports integer, active_ports integer, inactive_ports integer, peer_score integer, protected_score integer, \
             naked_score integer, exp_delta, avg_port_score integer, real_app_src_peers integer, ext_env_peers integer, port_1 text, port_1_pct_red float, \
             port_2 text, port_2_pct_red float, port_3 test, port_3_pct_red float, port_4 text, port_4_pct_red float, port_5 text, port_5_pct_red float)"
    cursor.execute(query)

  
    for wl in wldetail:

        if wl == []:
            continue
        
        try:
            uuid = wl['response']['href'].rsplit('/',1)[-1]
        except:
            sys.exit("wl = {0}".format(wl))
            
        hostname = wl['response'].get('hostname')
        loc, env, app, role = None, None, None, None
        for label in wl['response']['labels']:
            if label['key'] == 'loc':
                loc = label.get('value')
            elif label['key'] == 'env':
                env = label.get('value')
            elif label['key'] == 'app':
                app = label.get('app')
            elif label['key'] == 'role':
                role = label.get('role')
        href = wl['response']['href']
        state = wl['response']['agent']['config']['mode']

        query = "INSERT OR IGNORE INTO workloads(uuid,hostname,loc,env,app,role,href,state) VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}')".format(uuid,hostname,loc,env,app,role,href,state)

        cursor.execute(query)

    print("Finished creating Workload DB")


def createportdb(config, cursor, con, wldetail):

    cursor.execute("DROP TABLE IF EXISTS portdb")

    print("Creating portdb of workload listeners")
    counter = 0
    wlcount = len(wldetail)
    totalports = 0
    query = "CREATE TABLE IF NOT EXISTS portdb (uuid char(30), address, package, protocol_num, protocol_name, port, process, user,\
              win_service, risk_score INTEGER, flow_count INTEGER, source_peers INTEGER, peer_score INTEGER, possible_peers INTEGER, naked_score INTEGER);"
    cursor.execute(query)

    for wl in wldetail:
        uuid = wl['response']['href'].rsplit('/',1)[-1]
        portcount = len(wl['response']['services']['open_service_ports'])
        for entry in wl['response']['services']['open_service_ports']:

            address, package, protocol, port, process, user, win_service = None, None, None, None, None, None, None
            address = entry.get('address')
            package = entry.get('package')
            protocol = entry.get('protocol')
            protocol_name = changeprotocol(protocol)
            port = entry.get('port')
            process = entry.get('process_name')
            user = entry.get('user')
            win_service = entry.get('win_service_name')

            if "{0}/{1}".format(port,protocol_name) in config['services']['protocols']: 
                score = config['services']['protocols']["{0}/{1}".format(port,protocol_name)]
            elif "{0}".format(protocol_name) in config['services']['protocols']: 
                score = config['services']['protocols']["{0}/{1}".format(protocol_name)]
            else: 
                score = config['services']['protocols']['default']

            query = "INSERT OR IGNORE INTO portdb(uuid, address, package, protocol_num, protocol_name, port, process, user, win_service, risk_score) \
                     VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}','{9}');".format(
                        uuid, address, package, protocol, protocol_name, port, process, user, win_service, score
                     )
            
            cursor.execute(query)
        
        counter += 1
        totalports += portcount

        print("{0}/{1} Workloads, {2} ports added".format(counter, wlcount, totalports),end='\r')

        con.commit()
    
    print("\n")


def changeprotocol(protocol):

    if protocol == 1: protocol = 'icmp'
    elif protocol == 2: protocol = 'igmp'
    elif protocol == 6: protocol = 'tcp'
    elif protocol == 17: protocol = 'udp'
    elif protocol == 47: protocol = 'gre'
    elif protocol == 51: protocol = 'ah'
    elif protocol == 94: protocol = 'ipip'
    elif protocol == 103: protocol = 'pim'
    elif protocol == 112: protocol = 'vrrp'
    else: pass

    return protocol

def createtrafficdb(cursor, con):

    print("Creating traffic DB")

    # Uncomment next line to drop and refresh the traffic DB.
    #cursor.execute("drop table traffic")

    query = "CREATE TABLE IF NOT EXISTS traffic (uuid,Direction,ConsumerIP,ConsumerIPList,ConsumerName,ConsumerHostname,ConsumerManaged,ConsumerEnforcementMode,\
                                ConsumerApplication,ConsumerBusinessUnit,ConsumerEnvironment,ConsumerLocation,ConsumerRole,\
                                ConsumerType,ConsumingProcess,ConsumingService,ConsumingUsername,\
                                ProviderIP,ProviderIPList,ProviderName,ProviderHostname,ProviderManaged,ProviderEnforcementMode,\
                                ProviderApplication,ProviderBusinessUnit,ProviderEnvironment,ProviderLocation,ProviderRole,ProviderType,ProviderFQDN,\
                                Transmission,Port,Protocol,ProvidingProcess,ProvidingService,ProvidingUsername,NumFlows,ConnectionState,ReportedPolicyDecision,\
                                ReportedEnforcementBoundary,Reportedby,FirstDetected,LastDetected,Network,BytesIn,BytesOut)"
    cursor.execute(query)
    con.commit()


def populatetraffic(config, cursor, con, wllist):
   
    wlcount = len(wllist)
    counter = 0
    addcounter = 0
    for wl in wllist:
        counter += 1
        uuid = wl.rsplit('/',1)[-1]
        ## Check if a table exists for each workloads flows
        uuidexist = cursor.execute("SELECT count(*) FROM traffic WHERE uuid ='{0}';".format(uuid)).fetchone()

        if uuidexist[0] == 0:
      
            wldesttraffic, wlsourcetraffic = trafficquery(config,wl)

            try:
                with open('intemp.csv', 'w') as file:
                    file.write(wldesttraffic['response'])

                with open('intemp.csv', 'r') as trafficfile:
                    data = csv.DictReader(trafficfile)
                    direction = 'in'
                    writeflows(con,cursor,uuid,data,direction)
            except:
                print("No inbound flows found for {0}".format(uuid))

            try:
                with open('outtemp.csv', 'w') as file:
                    file.write(wlsourcetraffic['response'])

                with open('outtemp.csv', 'r') as trafficfile:
                    data = csv.DictReader(trafficfile)
                    direction = 'out'
                    writeflows(con,cursor,uuid,data,direction)
            except:
                print("No outbound flows found for {0}".format(uuid))
      

            query = "SELECT count(*) from traffic where uuid =  '{0}'".format(uuid)
            result = cursor.execute(query).fetchone()
            print("{0} connections added for {1}".format(result[0],uuid))
            addcounter += 1
            print("{0}/{1} Completed with {2} new workloads added".format(counter,wlcount, addcounter))

        else:

            print("{0}/{1} Completed with {2} new workloads added".format(counter,wlcount, addcounter),end='\r')
               


def writeflows(con, cursor, uuid, data, direction):
    to_db = [(uuid,direction,i['Consumer IP'],i['Consumer IPList'],i['Consumer Name'],i['Consumer Hostname'],i['Consumer Managed'],i['Consumer Enforcement Mode'],
            i['Consumer Application'],i['Consumer Business Unit'],i['Consumer Environment'],i['Consumer Location'],i['Consumer Role'],
            i['Consumer Type'],i['Consuming Process'],i['Consuming Service'],i['Consuming Username'],
            i['Provider IP'],i['Provider IPList'],i['Provider Name'],i['Provider Hostname'],i['Provider Managed'],i['Provider Enforcement Mode'],
            i['Provider Application'],i['Provider Business Unit'],i['Provider Environment'],i['Provider Location'],i['Provider Role'],i['Provider Type'],i['Provider FQDN'],
            i['Transmission'],i['Port'],i['Protocol'],i['Providing Process'],i['Providing Service'],i['Providing Username'],i['Num Flows'],i['Connection State'],i['Reported Policy Decision'],
            i['Reported Enforcement Boundary'],i['Reported by'],i['First Detected'],i['Last Detected'],i['Network'],i['Bytes In'],i['Bytes Out']) for i in data]

    query = "INSERT OR IGNORE INTO traffic (uuid,Direction,ConsumerIP,ConsumerIPList,ConsumerName,ConsumerHostname,ConsumerManaged,ConsumerEnforcementMode,\
                            ConsumerApplication,ConsumerBusinessUnit,ConsumerEnvironment,ConsumerLocation,ConsumerRole,\
                            ConsumerType,ConsumingProcess,ConsumingService,ConsumingUsername,\
                            ProviderIP,ProviderIPList,ProviderName,ProviderHostname,ProviderManaged,ProviderEnforcementMode,\
                            ProviderApplication,ProviderBusinessUnit,ProviderEnvironment,ProviderLocation,ProviderRole,ProviderType,ProviderFQDN,\
                            Transmission,Port,Protocol,ProvidingProcess,ProvidingService,ProvidingUsername,NumFlows,ConnectionState,ReportedPolicyDecision,\
                            ReportedEnforcementBoundary,Reportedby,FirstDetected,LastDetected,Network,BytesIn,BytesOut) VALUES (?{1});".format(uuid,",?"*45)

    cursor.executemany(query, to_db)
    con.commit()

    
def scoreports(config, cursor, con):
    # Get Stats on listening ports to measure scores, exposure and live flows
    query = "SELECT * FROM portdb"
    results = cursor.execute(query).fetchall()


    counter = 0
    for row in results:
        if counter < 10000:

            inflowquery = "SELECT SUM(NumFlows) FROM traffic where uuid = '{0}' and protocol = '{1}' and port = '{2}' and direction = 'in'".format(row[0],(row[4]).upper(),row[5])
            consumerpeerquery = "SELECT COUNT(DISTINCT(ConsumerIP)) from traffic where uuid = '{0}' and protocol = '{1}' and port = '{2}' and direction = 'in' ".format(row[0],(row[4]).upper(),row[5])
            

            flows = cursor.execute(inflowquery).fetchone()
            if not flows[0]:
                flowcount = 0
            else: 
                flowcount = flows[0]
            sourcepeers = cursor.execute(consumerpeerquery).fetchone()
            src_peer_score = int(row[9]) * sourcepeers[0]
            total_score = int(row[9]) * int(config['devicecount']['total'])

            updateportdb =  "UPDATE portdb SET flow_count = {0}, source_peers = {1}, peer_score = {2}, possible_peers = {3}, \
                            naked_score = {4} where uuid = '{5}' and protocol_name = '{6}' and port = '{7}'".format(
                            flowcount,sourcepeers[0], src_peer_score, config['devicecount']['total'],total_score,row[0],(row[4]).lower(),row[5]
                            )

            
            cursor.execute(updateportdb)
        counter += 1

    con.commit()



def scorewls(config, cursor, con, wllist):

    print("Adding workload stats to workloads")
  
    result = cursor.execute("WITH T1 AS ( \
                                SELECT uuid, p.protocol_name, port, possible_peers, risk_score, flow_count, source_peers, peer_score, naked_score \
                                FROM portdb p \
                                GROUP BY p.uuid, p.protocol_name, p.port \
                             ) \
                             SELECT T1.uuid, count(*) as listeners, \
                             SUM(CASE WHEN T1.source_peers > 0 THEN 1 ELSE 0 END) as used_ports, \
                             SUM(CASE WHEN T1.source_peers = 0 THEN 1 ELSE 0 END) as unused_ports, \
                             T1.possible_peers, \
                             SUM(T1.flow_count), sum(T1.source_peers), sum(T1.peer_score), sum(T1.risk_score) as exp_score, sum(T1.risk_score) * T1.possible_peers as naked_score \
                             FROM T1 \
                             GROUP BY T1.uuid"

                            ).fetchall()
    for x in result:
        
        exp_delta = 100 - (x[7] / x[9]) * 100 # Mitagated score = the real peer count / total exposed peers * 100

        cursor.execute("UPDATE workloads SET flows = {0}, exp_src_peers = {1}, exp_score = {2}, real_src_peers = {3}, total_src_flows = {4}, \
                                 total_ports = {5}, active_ports = {6}, inactive_ports = {7}, peer_score = {8}, naked_score = {9}, exp_delta = {10} where uuid = '{11}' ".format
                                (
                                 x[5], x[4], x[8], x[6], x[5], x[1], x[2], x[3], x[7], x[9], exp_delta, x[0]
                                ))
    con.commit()

 
    for wl in wllist:
        uuid = wl.rsplit('/',1)[-1]
        outflowquery = "SELECT SUM(NumFlows) FROM traffic where uuid = '{0}' and direction = 'out'".format(uuid)
        destpeerquery = "SELECT count(DISTINCT(ProviderIP)) from traffic where uuid = '{0}' and direction = 'out'".format(uuid)
        
        flows = cursor.execute(outflowquery).fetchone()
        if not flows[0]:
            flowcount = 0
        else: 
            flowcount = flows[0]
        destpeers = cursor.execute(destpeerquery).fetchall()

        cursor.execute("UPDATE workloads SET flows = flows + {0}, total_dst_flows = {0}, real_dst_peers = {1} where uuid = '{2}'".format(flowcount, destpeers[0][0], uuid))

    con.commit()

    



if __name__ == "__main__":
    main()
    