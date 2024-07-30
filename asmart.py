#!/usr/bin/env python

## Author: Russell Goodwin, Illumio inc. v0.0.2 - 18th July 2024.
## Python 3.12 script, requiring the asprequests wrapper


import asprequests
import json
import concurrent.futures
import datetime, time
import sqlite3 as db
from itertools import zip_longest
import csv
import sys
import os

MAX_THREADS = 10

def main():
    start = time.time()
    configfile = 'asmart.conf'
    config = getconfig(configfile)
    orgID = asprequests.getorg()
    getpcever(orgID)
    config['orgID'] = orgID

    cursor, con = createdb(orgID)
 
    wllist, workloads = getworkloads(orgID)

    builddb(config, cursor, con, workloads, wllist)

    analysedb(config, cursor, con, wllist)
    end = time.time()
    print("Data processing for {0} workloads took {1} seconds".format(len(wllist),round(end-start,2)))


def getpcever(orgID):
    # Get the PCE version and display it
    url = "/users/login".format(orgID)
    
    payload = asprequests.call(url)['response']
    try:
        if payload[0]['token'] == 'forbidden error':
            pass
            # Read only user won't get this infomation
    except:
        print("Illumio Core version: {0}".format(payload['product_version']['version']))


def builddb(config, cursor, con, workloads, wllist):

    # Build the various DB tables from API data
    createwldb(cursor, workloads)
    createportdb(config, cursor, con, workloads)
    createtrafficdb(cursor, con)
    populatetraffic(config, cursor, con, wllist)


def analysedb(config, cursor, con, wllist):

    # Use traffic data to score ports and worklaods for exposure and use
    scoreports(config, cursor, con)
    scorewls(config, cursor, con, wllist)


def grouper(iterable, n, *, incomplete='fill', fillvalue=None):

    # Module from more-iter-tools to support multithreading for API calls
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

    # Get the config file, thats it.
    with open(configfile) as conf:
        config = json.load(conf)
    return config


def createdb(orgID):

    # Open an existing SQLite DB, or create one if it doesn't exist.
    # The DB will contain workload details and stats, as well as traffic data
    # We will collect flow data via the traffic API, insert it into the DB and then perform SQL analytics
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
    
    ## Get all workloads.
    url = "/orgs/{0}/workloads?representation=workload_labels&managed=true".format(orgID)
    
    workloads = asprequests.call(url)['response']

    # Use the sync API first. If we find 500 workloads, assume there are more and that the async call is needed.
    if len(workloads) == 500:
        print("Found 500+ Workloads, using Async fetch")
        workloads = asprequests.bulk(url)['response']
    
    # Bulk workload API does not provide listening ports to score by. So each Workload needs collecting.
    # Note, this is not iterated with a counter as its multi-threaded.

    print("Collecting detail for {0} matching workloads".format(len(workloads)))

    wldetail = []
    
    # Run the Workload API requests in multiple threads
    def thread_workloads(workloads):
        for workload in workloads:
            
            wllist.append(workload['hostname'])

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
    

def buildbulktrafficquery(queryhours):
    # Constructs a query to get all traffic for all workloads. Works fine if there are less than 200k total. For more, it needs breaking up.
    querystart = ((datetime.datetime.now() - datetime.timedelta(hours=queryhours)).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    queryend = (datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z"))

    bulkquery = {"boundary_decisions":[],"destinations":{"exclude":[],"include":[[]]},"end_date":queryend,
             "exclude_workloads_from_ip_list_query":True,"max_results":200000,"policy_decisions":[],"query_name":"Source Traffic Query for Exposure tool",
             "services":{"exclude":[],"include":[]},"sources":{"exclude":[],"include":[[]]},"sources_destinations_query_op":"and","start_date":querystart}
    
    return bulkquery


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


def bulktrafficquery(config):
    # Run a traffic query for all traffic for the configured time interval

    href = "/orgs/{0}/traffic_flows/async_queries".format(config['orgID'])
    
    bulkquery = buildbulktrafficquery(config['queryhours'])

    counter = 0
    success = False

    while counter < 3 and success != True:
        try:
            results = asprequests.traffic(url=href,payload=bulkquery)
            if results['HTTPcode'] == 200:
                success = True
                    
        except:
            results = []

        counter += 1

    return results

 
def trafficquery(config, wl):

    # Run a traffic query for all traffic destined and sourced to/from a given WL href for the configured time interval
    # Not currently used as all traffic is collected in bulk. But will be needed for larger deployments with > 200k flows.
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

    # Create a DB for the workloads. This will contain workload details such as UUID, name and labels. Will also be decorated with WL flow data and scores.

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
                app = label.get('value')
            elif label['key'] == 'role':
                role = label.get('value')
    
        href = wl['response']['href']
        state = wl['response']['agent']['config']['mode']

        query = "INSERT OR IGNORE INTO workloads(uuid,hostname,loc,env,app,role,href,state) VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}')".format(uuid,hostname,loc,env,app,role,href,state)

        cursor.execute(query)

    print("Finished creating Workload DB")


def createportdb(config, cursor, con, wldetail):

    # The Port DB is a list of all listeners on managed workloads. Each listener will be scored based on risk, expsosure, active flow count etc.

    cursor.execute("DROP TABLE IF EXISTS portdb")

    print("Creating portdb of workload listeners")
    counter = 0
    wlcount = len(wldetail)
    totalports = 0
    query = "CREATE TABLE IF NOT EXISTS portdb (uuid char(30), address, hostname, package, protocol_num, protocol_name, port, process, user,\
              win_service, risk_score INTEGER, flow_count INTEGER, source_peers INTEGER, peer_score INTEGER, possible_peers INTEGER, naked_score INTEGER);"
    cursor.execute(query)

    for wl in wldetail:
        hostname = wl['response'].get('hostname')

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

            query = "INSERT OR IGNORE INTO portdb(uuid, address, hostname, package, protocol_num, protocol_name, port, process, user, win_service, risk_score) \
                     VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}','{9}','{10}');".format(
                        uuid, address, hostname, package, protocol, protocol_name, port, process, user, win_service, score
                     )
            
            cursor.execute(query)
        
        counter += 1
        totalports += portcount

        print("{0}/{1} Workloads, {2} ports added".format(counter, wlcount, totalports),end='\r')

        con.commit()
    
    print("\n")


def changeprotocol(protocol):

    # Change the protocols we may see to a human readable format

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

    # Traffic BD will contain entries for all flows found from the API. Much of the heavy lifting is querying of this data for analytics related to workloads.

    print("Creating traffic DB")

    # Clean the DB on fresh runs
    cursor.execute("DROP TABLE IF EXISTS traffic")

    query = "CREATE TABLE IF NOT EXISTS traffic (uuid,Direction,ConsumerIP,ConsumerIPList,ConsumerName,ConsumerHostname,ConsumerManaged,ConsumerEnforcementMode,\
                                ConsumerApplication,ConsumerEnvironment,ConsumerLocation,ConsumerRole,\
                                ConsumerType,ConsumingProcess,ConsumingService,ConsumingUsername,\
                                ProviderIP,ProviderIPList,ProviderName,ProviderHostname,ProviderManaged,ProviderEnforcementMode,\
                                ProviderApplication,ProviderEnvironment,ProviderLocation,ProviderRole,ProviderFQDN,\
                                Transmission,Port,Protocol,ProvidingProcess,ProvidingService,ProvidingUsername,NumFlows,ConnectionState,ReportedPolicyDecision,\
                                ReportedEnforcementBoundary,Reportedby,FirstDetected,LastDetected,Network,BytesIn,BytesOut)"
    cursor.execute(query)
    con.commit()


def populatetraffic(config, cursor, con, wllist):
    print("Attempting to fetch traffic data for all {0} workloads".format(len(wllist)))
    alltraffic = bulktrafficquery(config)
    

    try:
        with open('traffictemp.csv', 'w') as file:
            file.write(alltraffic['response'])
        with open('traffictemp.csv', 'r') as file:
            data = csv.DictReader(file)
            uuid,direction = None, None
            writeflows(con,cursor,uuid,data,direction)


    except:
        print("failed to write traffic data")
    

    # If a bulk query doesnt get all the traffic, go get it per Workload. Not yet enabled.
    # NOTE : THIS WILL TAKE TIME
    #populatewltraffic(config, cursor, con, wllist)


def populatewltraffic(config, cursor, con, wllist):
       
    wlcount = len(wllist)
    counter = 0
    addcounter = 0
    for wl in wllist:
        counter += 1
        uuid = wl.rsplit('/',1)[-1]
        ## Check if a entry exists for each workloads flows
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
            
            try: 
                os.remove('intemp.csv')
                os.remove('outtemp.csv')
            except OSError:
                print("failed to delete temp files")
                pass
      

            query = "SELECT count(*) from traffic where uuid =  '{0}'".format(uuid)
            result = cursor.execute(query).fetchone()
            print("{0} connections added for {1}".format(result[0],uuid))
            addcounter += 1
            print("{0}/{1} Completed with {2} new workloads added".format(counter,wlcount, addcounter))

        else:

            print("{0}/{1} Completed with {2} new workloads added".format(counter,wlcount, addcounter),end='\r')
               


def writeflows(con, cursor, uuid, data, direction):

    # Write flows to local sqlite database based on data from Traffic API

    to_db = [(uuid,direction,i['Source IP'],i['Source IPList'],i['Source Name'],i['Source Hostname'],i['Source Managed'],i['Source Enforcement Mode'],
            i['Source Application'],i['Source Environment'],i['Source Location'],i['Source Role'],
            i['Source Process'],i['Source Service'],i['Source Username'],
            i['Destination IP'],i['Destination IPList'],i['Destination Name'],i['Destination Hostname'],i['Destination Managed'],i['Destination Enforcement Mode'],
            i['Destination Application'],i['Destination Environment'],i['Destination Location'],i['Destination Role'],i['Destination FQDN'],
            i['Transmission'],i['Port'],i['Protocol'],i['Destination Process'],i['Destination Service'],i['Destination Username'],i['Num Flows'],i['Connection State'],i['Reported Policy Decision'],
            i['Reported Enforcement Boundary'],i['Reported by'],i['First Detected'],i['Last Detected'],i['Network'],i['Bytes In'],i['Bytes Out']) for i in data]
    
    print("Inserting {0} traffic flow relationships into local DB".format(len(to_db)))

    query = "INSERT OR IGNORE INTO traffic (uuid,Direction,ConsumerIP,ConsumerIPList,ConsumerName,ConsumerHostname,ConsumerManaged,ConsumerEnforcementMode,\
                            ConsumerApplication,ConsumerEnvironment,ConsumerLocation,ConsumerRole,\
                            ConsumingProcess,ConsumingService,ConsumingUsername,\
                            ProviderIP,ProviderIPList,ProviderName,ProviderHostname,ProviderManaged,ProviderEnforcementMode,\
                            ProviderApplication,ProviderEnvironment,ProviderLocation,ProviderRole,ProviderFQDN,\
                            Transmission,Port,Protocol,ProvidingProcess,ProvidingService,ProvidingUsername,NumFlows,ConnectionState,ReportedPolicyDecision,\
                            ReportedEnforcementBoundary,Reportedby,FirstDetected,LastDetected,Network,BytesIn,BytesOut) VALUES (?{1});".format(uuid,",?"*41)
    
    cursor.executemany(query, to_db)
    con.commit()

    
def scoreports(config, cursor, con):
    # Get Stats on listening ports to measure scores, exposure and live flows
    query = "SELECT * FROM portdb"
    results = cursor.execute(query).fetchall()
    resultscount = len(results)


    counter = 0
    for row in results:

        print("Updating risk scoring data for {0}/{1} listening ports".format(counter+1,resultscount),end='\r')

        # Query the total flows 

        inflowquery = "SELECT SUM(NumFlows) FROM traffic where (ProviderHostname = '{0}' or ProviderName = '{0}') and protocol = '{1}' and port = '{2}' and Reportedby = 'Destination'".format(row[2],(row[5]).upper(),row[6])
        consumerpeerquery = "SELECT COUNT(DISTINCT(ConsumerIP)) from traffic where (ProviderHostname = '{0}' or ProviderName = '{0}') and protocol = '{1}' and port = '{2}' and Reportedby = 'Destination' ".format(row[2],(row[5]).upper(),row[6])

        flows = cursor.execute(inflowquery).fetchone()
        if not flows[0]:
            flowcount = 0
        else: 
            flowcount = flows[0]

        sourcepeers = cursor.execute(consumerpeerquery).fetchone()

        src_peer_score = int(row[10]) * sourcepeers[0]
        total_score = int(row[10]) * int(config['devicecount']['total'])

        updateportdb =  "UPDATE portdb SET flow_count = {0}, source_peers = {1}, peer_score = {2}, possible_peers = {3},naked_score = {4} where hostname = '{5}' and protocol_name = '{6}' and port = '{7}'".format(
                        flowcount,sourcepeers[0], src_peer_score, config['devicecount']['total'],total_score,row[2],(row[5]).lower(),row[6]
                        )

        cursor.execute(updateportdb)
        counter += 1

    con.commit()

    print("\n")


def scorewls(config, cursor, con, wllist):
    # Collect data from portdb risk information and add associated scoring data to workloads.
    print("Adding workload scoring stats to workloads")
  
    # Query to collect scores from PortDB on a per workload basis. Grouped by Workload, so these are aggregated stats for the workload based on the portdb info
    result = cursor.execute("WITH T1 AS ( \
                                SELECT hostname, p.protocol_name, port, possible_peers, risk_score, flow_count, source_peers, peer_score, naked_score \
                                FROM portdb p \
                                GROUP BY p.hostname, p.protocol_name, p.port \
                             ) \
                             SELECT T1.hostname, count(*) as listeners, \
                             SUM(CASE WHEN T1.source_peers > 0 THEN 1 ELSE 0 END) as used_ports, \
                             SUM(CASE WHEN T1.source_peers = 0 THEN 1 ELSE 0 END) as unused_ports, \
                             T1.possible_peers, \
                             SUM(T1.flow_count), sum(T1.source_peers), sum(T1.peer_score), sum(T1.risk_score) as exp_score, sum(T1.risk_score) * T1.possible_peers as naked_score \
                             FROM T1 \
                             GROUP BY T1.hostname"

                            ).fetchall()
    
    totalcount = len(result)
    currentcount = 1

    # For each row, containing aggregated data for each workload, add those stats to the workload DB for related workloads.
    for x in result:
        
        print("Updating {0}/{1} Workloads".format(currentcount, totalcount), end="\r")

        exp_delta = 100 - (x[7] / x[9]) * 100 # Mitigated score = the percentage value of risk reduction from an unprotected workload to one locked down base down observed flows

        '''
        Values added to workload data based on portDB and traffic
        flows           = total number of reported flows to and from this workload. Flows destined to listning ports, added to outbound flows from the workload
        exp_src_peers   = total possible exposed source peers, assuming no protection
        exp_score       = workload risk score, based on its exposed ports and their risk values
        real_src_peers  = actual sources of traffic to this workload on this port
        total_src_flows = Total flows coming into the workload from source peers
        total_ports     = number of ports listening on the host
        active_ports    = number of ports listening and receiving 1 or more flows
        inactiveports   = number of ports listening with zero inbound flows seen in traffic data
        peer_score      = total risk score based on inbound usage of ports, their risk and their active source peers  
        naked_score     = total risk score based on all listening ports and all possible peers
        exp_delta       = the percentage mitigation, where the peer score is divided by the naked score to work out the reduction with policy locked down to just observed flows

        '''
        cursor.execute("UPDATE workloads SET flows = {0}, exp_src_peers = {1}, exp_score = {2}, real_src_peers = {3}, total_src_flows = {4}, \
                                 total_ports = {5}, active_ports = {6}, inactive_ports = {7}, peer_score = {8}, naked_score = {9}, exp_delta = {10} where hostname = '{11}' ".format
                                (
                                 x[5], x[4], x[8], x[6], x[5], x[1], x[2], x[3], x[7], x[9], exp_delta, x[0]
                                ))
        
        currentcount += 1

    con.commit()
    print("\n")

    # Add outbound flow data. This is done seperatly as it isn't associated with a workloads own risk rating and just used for top talker stats etc.

    totalcount = len(wllist)
    currentcount = 1
    for wl in wllist:

        print("Adding outbound flow stats to workloads: {0}/{1}".format(currentcount, totalcount), end="\r")

        outflowquery = "SELECT SUM(NumFlows) FROM traffic where (ConsumerHostname = '{0}' or ConsumerName = '{0}') and Reportedby = 'Source'".format(wl)
        destpeerquery = "SELECT count(DISTINCT(ProviderIP)) from traffic where (ConsumerHostname = '{0}' or ConsumerName = '{0}')  and Reportedby = 'Source'".format(wl)
        
        flows = cursor.execute(outflowquery).fetchone()
        if not flows[0]:
            flowcount = 0
        else: 
            flowcount = flows[0]
        destpeers = cursor.execute(destpeerquery).fetchall()

        cursor.execute("UPDATE workloads SET flows = flows + {0}, total_dst_flows = {0}, real_dst_peers = {1} where hostname = '{2}'".format(flowcount, destpeers[0][0], wl))
        
        currentcount += 1

    con.commit()

    print("\n")

    
if __name__ == "__main__":
    main()
    