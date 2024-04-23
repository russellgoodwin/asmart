import sqlite3 as db#
import asprequests
import csv
import json

def main():

    configfile = 'asmart.conf'
    config = getconfig(configfile)

    orgID = asprequests.getorg()
    cursor, con = opendb(orgID)
    queries(cursor, config)
    con.close()

def getconfig(configfile):
    with open(configfile) as conf:
        config = json.load(conf)
    return config

def opendb(orgID):
    # Open the existing SQLite DB, containing workload details and stats, as well as traffic data

    con = db.connect('file:{}.db?mode=rw'.format(orgID), uri=True)
    print("Opened existing DB: {0}.db".format(orgID))

    cursor = con.cursor()

    return cursor, con


def queries(cursor,config):
 
    #workloads = cursor.execute("SELECT uuid from workloads").fetchall()

    result = cursor.execute("SELECT COUNT(*) FROM workloads").fetchone()
    print("{} Workloads in dataset".format(result[0]))

    #print("portdb extract starts")

    #print("portdb extract ends")
 
    filename = 'output.csv'
    wlstats(cursor, filename)
    portstats(cursor,filename, config)
    labelstats(cursor, filename)



    


def wlstats(cursor, filename):

    query = "select hostname,loc,env,app,role,state,flows,exp_src_peers,exp_score,real_src_peers,real_dst_peers,\
             total_src_flows,total_dst_flows,total_ports,active_ports,inactive_ports,peer_score,naked_score,ROUND(exp_delta,3)"

    allwls = cursor.execute("{0} from workloads".format(query)).fetchall()

    topdstflows = cursor.execute("{0} from workloads order by total_dst_flows DESC limit 10".format(query)).fetchall()
    
    topsrcflows = cursor.execute("{0} from workloads order by total_src_flows DESC limit 10".format(query)).fetchall()
    
    topdstpeers = cursor.execute("{0} from workloads order by real_dst_peers DESC limit 10".format(query)).fetchall()
    
    topsrcpeers = cursor.execute("{0} from workloads order by real_src_peers DESC limit 10".format(query)).fetchall()
    
    topbothpeers = cursor.execute("{0}, (real_src_peers + real_dst_peers) as total_peers from workloads order by total_peers DESC limit 10".format(query)).fetchall()
    
    topexpmitigation = cursor.execute("{0} from workloads order by exp_delta DESC limit 10".format(query)).fetchall()
    
    topriskports = cursor.execute("{0} from workloads order by exp_score DESC limit 10".format(query)).fetchall()
    
  

    #for row in output:
    #    print(row)

    columns = ['hostname','loc','env','app','role','state','flows','exp_src_peers','exp_score','real_src_peers','real_dst_peers',
               'total_src_flows','total_dst_flows','total_ports','active_ports','inactive_ports','peer_score','naked_score','mitigation']
    
    print("Writing file '{0}'".format(filename))
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['all workloads'])
        writer.writerow(columns)
        writer.writerows(allwls)
        writer.writerow('')
        writer.writerow(['top talkers'])
        writer.writerow(columns)
        writer.writerows(topdstflows)
        writer.writerow('')
        writer.writerow(['top listeners'])
        writer.writerow(columns)
        writer.writerows(topsrcflows)
        writer.writerow('')
        writer.writerow(['top dst peers'])
        writer.writerow(columns)
        writer.writerows(topdstpeers)
        writer.writerow('')
        writer.writerow(['top src peers'])
        writer.writerow(columns)
        writer.writerows(topsrcpeers)
        writer.writerow('')
        writer.writerow(['top total peers'])
        writer.writerow(columns)
        writer.writerows(topbothpeers)
        writer.writerow('')
        writer.writerow(['top risk exposed wls'])
        writer.writerow(columns)
        writer.writerows(topexpmitigation)
        writer.writerow('')
        writer.writerow(['top risk score wls'])
        writer.writerow(columns)
        writer.writerows(topriskports)

def portstats(cursor,filename, config):

    services = sorted(config['services']['protocols'].items(), key = lambda kv: kv[1], reverse=True)

    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['High Risk Open ports'])

        counter = 0

        if counter < 10:
            for x in services:
                protocol = x[0].rsplit('/')[-1]
                port = x[0].rsplit('/')[0]

                porthosts = cursor.execute("select count(*) \
                                        FROM workloads w\
                                        JOIN portdb p\
                                        ON w.uuid = p.uuid\
                                        where p.protocol_name = '{0}' and p.port = '{1}' ".format(protocol, port)).fetchall()
                
                if porthosts[0][0] > 0:
                    writer.writerow(['{0}/{1}'.format(port,protocol),porthosts[0][0]])

                counter += 1


    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['High Risk Used ports'])

        counter = 0

        if counter < 10:
            for x in services:
                protocol = x[0].rsplit('/')[-1]
                port = x[0].rsplit('/')[0]

                porthosts = cursor.execute("select count(*) \
                                        FROM workloads w\
                                        JOIN portdb p\
                                        ON w.uuid = p.uuid\
                                        where p.protocol_name = '{0}' and p.port = '{1}' and flow_count > 0 ".format(protocol, port)).fetchall()
                
                if porthosts[0][0] > 0:
                    writer.writerow(['{0}/{1}'.format(port,protocol),porthosts[0][0]])
                
                counter += 1


    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['High Risk Unused ports'])

        counter = 0

        
        for x in services:
            if counter < 10:
                protocol = x[0].rsplit('/')[-1]
                port = x[0].rsplit('/')[0]

                porthosts = cursor.execute("select count(*) \
                                        FROM workloads w\
                                        JOIN portdb p\
                                        ON w.uuid = p.uuid\
                                        where p.protocol_name = '{0}' and p.port = '{1}' and flow_count = 0 ".format(protocol, port)).fetchall()
                
                if porthosts[0][0] > 0:
                    writer.writerow(['{0}/{1}'.format(port,protocol),porthosts[0][0]])

                counter += 1
            else: 
                break


def labelstats(cursor, filename):
    envquery = cursor.execute("SELECT ConsumerEnvironment, ProviderEnvironment, COUNT(*) AS conncount, SUM(NumFlows) as flows  FROM traffic \
                               WHERE ConsumerEnvironment != ProviderEnvironment \
                               GROUP BY ConsumerEnvironment,ProviderEnvironment \
                               ORDER BY conncount desc, ConsumerEnvironment,ProviderEnvironment ").fetchall()
    

    consumerappquery = cursor.execute(
                                "SELECT ConsumerApplication, COUNT(*) as AppPeers, SUM(NumFlows) as flows  FROM \
                                    ( \
                                        SELECT ConsumerApplication, ProviderApplication, SUM(NumFlows) as NumFlows \
                                        FROM traffic group by ConsumerApplication, ProviderApplication \
                                    )  \
                                 GROUP BY ConsumerApplication \
                                 ORDER BY AppPeers DESC, ConsumerApplication"
                             ).fetchall() 
    

    consumerappgroupquery = cursor.execute(
                                "SELECT ConsumerApplication, ConsumerEnvironment, COUNT(*) as AppPeers, SUM(NumFlows) as flows  FROM \
                                    ( \
                                        SELECT ConsumerApplication, ConsumerEnvironment, ProviderApplication, ProviderEnvironment, SUM(NumFlows) as NumFlows \
                                        FROM traffic \
                                        GROUP BY ConsumerApplication, ConsumerEnvironment, ProviderApplication, ProviderEnvironment \
                                    ) \
                                 GROUP BY ConsumerApplication, ConsumerEnvironment \
                                 ORDER BY AppPeers DESC, ConsumerApplication, ConsumerEnvironment"
                             ).fetchall() 
    
    providerappquery = cursor.execute(
                                "SELECT ProviderApplication, COUNT(*) as AppPeers, SUM(NumFlows) as flows  FROM \
                                    ( \
                                        SELECT ConsumerApplication, ProviderApplication, SUM(NumFlows) as NumFlows \
                                        FROM traffic group by ConsumerApplication, ProviderApplication \
                                    )  \
                                 GROUP BY ProviderApplication \
                                 ORDER BY AppPeers DESC, ProviderApplication"
                             ).fetchall() 
    

    providerappgroupquery = cursor.execute(
                                "SELECT ProviderApplication, ProviderEnvironment, COUNT(*) as AppPeers, SUM(NumFlows) as flows  FROM \
                                    ( \
                                        SELECT ConsumerApplication, ConsumerEnvironment, ProviderApplication, ProviderEnvironment, SUM(NumFlows) as NumFlows \
                                        FROM traffic \
                                        GROUP BY ConsumerApplication, ConsumerEnvironment, ProviderApplication, ProviderEnvironment \
                                    ) \
                                 GROUP BY ProviderApplication, ProviderEnvironment \
                                 ORDER BY AppPeers DESC, ProviderApplication, ProviderEnvironment"
                             ).fetchall() 
    
    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['Destination App Peers'])
        writer.writerow(['Source App', 'App Peers', 'Flow Count'])
        counter = 0

        for row in consumerappquery:
             if row[1] > 0 and counter < 10:
                if row[0] == '': 
                   app = 'none'
                else: app = row[0]

                writer.writerow([app,row[1],row[2]])
                counter += 1


    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['Destination App Group Peers'])
        writer.writerow(['Source App', 'Source Env', 'App Peers', 'Flow Count'])
        counter = 0

        for row in consumerappgroupquery:

            if row[2] > 0 and counter < 10:
                if row[0] == '': 
                    app = 'none'
                else: app = row[0]
                if row[1] == '': 
                   env = 'none'
                else: env = row[1]

                writer.writerow([app,env,row[2],row[3]])
                counter += 1

    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['Source App Peers'])
        writer.writerow(['Destination App', 'App Peers', 'Flow Count'])
        counter = 0

        for row in providerappquery:
             if row[1] > 0 and counter < 10:
                if row[0] == '': 
                   app = 'none'
                else: app = row[0]

                writer.writerow([app,row[1],row[2]])
                counter += 1


    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['Source App Group Peers'])
        writer.writerow(['Detination App', 'Destination Env', 'App Peers', 'Flow Count'])
        counter = 0

        for row in providerappgroupquery:

            if row[2] > 0 and counter < 10:
                if row[0] == '': 
                    app = 'none'
                else: app = row[0]
                if row[1] == '': 
                   env = 'none'
                else: env = row[1]

                writer.writerow([app,env,row[2],row[3]])
                counter += 1

    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')
        writer.writerow(['Inter env connections'])
        writer.writerow(['Source Env', 'Dest Env', 'Unique connections', 'Flow Count'])
        counter = 0

        for row in envquery:
            if row[2] > 0 and counter < 10:
                if row[0] == '': 
                   srcenv = 'none'
                else: srcenv = row[0]
                if row[1] == '': 
                   dstenv = 'none'
                else: dstenv = row[1]
                writer.writerow([srcenv,dstenv,row[2],row[3]])
                counter += 1


if __name__ == "__main__":
    main()
    