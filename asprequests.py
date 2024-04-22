#!/usr/bin/env python

'''
All rights reservered Illumio inc, 2017.
asprequests.py for python3 - Version 1.0.0 - 18-Mar-2024
Author Russell Goodwin (russell@illumio.com)

This script provides an abstraction into a number of common ASP API interfaces.

You can call this script directly with command line arguments, 
or import it as a module and call methods directly with asprest.call or asprest.bulk

see ./asprequests.py --help for details on command line usage

Complete API key details in the config file 'asprequests.conf'  to direct and provide access to your PCE

'''

import requests
import ssl
import json
import base64
import sys
import time
import ast
import configparser
import argparse


## Set some global variables
settings = configparser.ConfigParser()
settings.read('asprequests.conf')

defaultFQDN = settings.get('pce','defaultFQDN')
defaultPort = settings.get('pce','defaultPort')
orgID = settings.get('pce','orgID')
apiVersion = settings.get('pce','apiVersion')

baseURL = "https://{0}:{1}/api/{2}".format(defaultFQDN,defaultPort,apiVersion)
authdata = (settings.get('user','apikey'), settings.get('user','apisecret'))

def main():

    #ssl._create_default_context = ssl._create_unverified_context

    parser=argparse.ArgumentParser(
        description='''Python module to interact with Illumio ASP API.''',
        epilog='''All rights reserved, Illumio inc. 2024''')

    parser.add_argument("-u", "--url", help="URL to pass to the PCE. URL should anchor on the API version, e.g. 'orgs/1/....'. You do not need to provide '/api/v[x]/'", action="store")
    parser.add_argument("-m", "--method", choices=['GET','PUT','POST','DELETE'], help="HTTP method to use", action="store")
    parser.add_argument("-p", "--payload", help="Payload to send for PUT or POST methods")
    parser.add_argument("--bulk", help="Specify a bulk method for GET requests of over 500 results", action="store_true")
    args, unknown = parser.parse_known_args()
    if not args.method:
        args.method = 'GET'

    if args.bulk and args.method == 'GET':
        output =  bulk(args.url)

    if args.bulk and args.method != 'GET':
        sys.exit("--bulk is for use only with GET requests")
        

    else:
        output = call(args.url,args.method,args.payload)

    if output['response']:
        print( output['response'])
    else:
        print("%s (HTTP code:%s)" % (output['result'],output['HTTPcode']))


def getorg():
    return orgID


def call(url,method='GET',payload=None):
    if not url:
        sys.exit("Please provide an API endpoint to query")
    start = time.time()
    requestURL = baseURL + url
    response = {'response':None,'HTTPcode':None,'HTTPresponse':None,'error':None,'recordcount':None,\
                'requestedURL':requestURL,'payload':None,'requesttime':time.strftime("%c"),'method':method,'result':None}

    if method == 'GET':
        apiRequest = requests.get(requestURL, auth=authdata)
    elif method == 'DELETE':
        apiRequest = requests.delete(requestURL, auth=authdata)
    elif method == 'PUT':
        apiRequest = requests.put(requestURL, auth=authdata, data=payload)
    elif method == 'POST':
        apiRequest = requests.post(requestURL, auth=authdata, data=payload)
    else:
        sys.exit("Unknown method")

    try:

        try:
            response['response'] = json.loads(apiRequest.text)
            response['HTTPcode'] = apiRequest.status_code
        except:
            response['response'] = None
            response['HTTPcode'] = apiRequest.status_code
            response['result'] = 'success'
        if response['response']:
            if type(response['response']) is list:
                response['recordcount'] = len(response['response'])
            else:
                response['recordcount'] = 1
    except apiRequest.ConnectionError as e:
        try:
            response['error'] = e.reason
            if not response['result']:
                response['result'] = "error: {0} for {1}".format(e.reason,defaultFQDN)
            response['HTTPcode'] = e.code
        except AttributeError:
            response['error'] = e
            if not response['result']:
                response['result'] = "error: {0} for {1}".format(e,defaultFQDN)
            response['HTTPcode'] = "N/A"

    except apiRequest.HTTPError as e:
        try:
            response['error'] = e.reason
            if not response['result']:
                response['result'] = "error: %{0} for {1}".format(e.reason,defaultFQDN)
        except AttributeError:
            response['error'] = e
            if not response['result']:
                response['result'] = "error: {0} for {1}".format(e,defaultFQDN)

    finish = time.time()
    response['responsetime'] = "%.3f" % (finish - start)
    return response


def bulk(url):
    ## Function to call the async API
    if not url:
        sys.exit("Please provide an API endpoint to query")
    start = time.time()
    requestURL = baseURL + url
    response = {'response':None,'HTTPcode':None,'HTTPresponse':None,'error':None,'recordcount':None,\
                'requestedURL':requestURL,'requesttime':time.strftime("%c"),'method':'async-get'}
    headers = {'Prefer': 'respond-async'}
    jobLocation = None
    fileLocation = None

    try:
        jobLocation = requests.get(requestURL, auth=authdata, headers=headers).headers['Location']
    except:
        print("Error starting async job")

    print("Fetching async job from {}".format(defaultFQDN))
    #print("Job Location: {}".format(jobLocation))
    if jobLocation:
        ## Monitor the async job until its done
        requestURL = baseURL + jobLocation
        #print("fetching job with URL: {}".format(requestURL))
     
        while True:
            try:
                apiRequest = requests.get(url=requestURL,auth=authdata)
                print("Fetched! {}".format(apiRequest.text))
                result = json.loads(apiRequest.text)
                status = result['status']
            except requests.HTTPError as e:
                response['error'] = e.reason
                response['HTTPcode'] = e.code
            except requests.ConnectionError as e:
                response['error'] = e.reason
                status = result['status']
            if status == "done":
                #print("Job complete!      ")
                fileLocation = result['result']['href']
                #print("Job results location is {}".format(fileLocation))
                break
            else:
                print("Job is %s...\r" % (status),)
                sys.stdout.flush()
                time.sleep(1)

    if fileLocation:
        ## Once job is complete, go and collect it
        url = baseURL + fileLocation
        apiRequest = requests.get(url=url,auth=authdata)

    try:

        try:
            response['response'] = json.loads(apiRequest.text)
        except:
            response['response'] = None
            response['HTTPcode'] = apiRequest.status_code
            response['result'] = 'success'
        if response['response']:
            if type(response['response']) is list:
                response['recordcount'] = len(response['response'])
            else:
                response['recordcount'] = 1
    except apiRequest.ConnectionError as e:
        try:
            response['error'] = e.reason
            if not response['result']:
                response['result'] = "error: {0} for {1}".format(e.reason,defaultFQDN)
            response['HTTPcode'] = e.code
        except AttributeError:
            response['error'] = e
            if not response['result']:
                response['result'] = "error: {0} for {1}".format(e,defaultFQDN)
            response['HTTPcode'] = "N/A"

    except apiRequest.HTTPError as e:
        try:
            response['error'] = e.reason
            if not response['result']:
                response['result'] = "error: %{0} for {1}".format(e.reason,defaultFQDN)
        except AttributeError:
            response['error'] = e
            if not response['result']:
                response['result'] = "error: {0} for {1}".format(e,defaultFQDN)

    finish = time.time()
    response['responsetime'] = "%.3f" % (finish - start)
    return response


def traffic(url,payload):
    ## Function to call the traffic async API
    if not url:
        sys.exit("Please provide an API endpoint to query")
    start = time.time()
    requestURL = baseURL + url
    response = {'response':None,'HTTPcode':None,'HTTPresponse':None,'error':None,'recordcount':None,\
                'requestedURL':requestURL,'requesttime':time.strftime("%c"),'method':'async-get'}
    jobLocation = None
    fileLocation = None

    result = requests.post(requestURL, json=payload, auth=authdata).text

    try:

        result = requests.post(requestURL, json=payload, auth=authdata)
    except:
        print("Error starting traffic request job")


    if result.status_code > 399:
        #sys.exit("Job location query failed with error: {}".format(result.raise_for_status))

        response['HTTPcode'] = result.status_code
    

    jobLocation = json.loads(result.text)['href']

    if jobLocation:

        print("Fetching async traffic query from {}".format(defaultFQDN))
        print("Job Location: {}".format(jobLocation))
        ## Monitor the async job until its done
        requestURL = baseURL + jobLocation
        #print("fetching job with URL: {}".format(requestURL))
     


        while True:

            try:
                apiRequest = requests.get(url=requestURL,auth=authdata)
                #result = json.loads(apiRequest.text)
                result = json.loads(apiRequest.text)
                status = result['status']
                                
            except requests.HTTPError as e:
                response['error'] = e.reason
                response['HTTPcode'] = e.code

                status = result['status']
            except requests.ConnectionError as e:
                response['error'] = e.reason
                status = result['status']

            if status == "completed":
                print("Job complete!      ")
                fileLocation = result['result']
                #print("Job results location is {}".format(fileLocation))
                break
        
            if status == "failed":
                response['HTTPcode'] = 400
                return response
            
            else:
                print("Job is {0}...".format(status),end='\r')
                sys.stdout.flush()
                time.sleep(1)

        
                

    if fileLocation:
        ## Once job is complete, go and collect it

        url = baseURL + fileLocation + "?offset=0"
        print("Fetching job results from {}".format(url))
        apiRequest = requests.get(url=url,auth=authdata)

        try:

            try:
                response['response'] = apiRequest.text
                response['HTTPcode'] = apiRequest.status_code
            except:
                response['response'] = None
                response['HTTPcode'] = apiRequest.status_code
                response['result'] = 'success'
            if response['response']:
                if type(response['response']) is list:
                    response['recordcount'] = len(response['response'])
                else:
                    response['recordcount'] = 1
        except apiRequest.ConnectionError as e:
            try:
                response['error'] = e.reason
                if not response['result']:
                    response['result'] = "error: {0} for {1}".format(e.reason,defaultFQDN)
                response['HTTPcode'] = e.code
            except AttributeError:
                response['error'] = e
                if not response['result']:
                    response['result'] = "error: {0} for {1}".format(e,defaultFQDN)
                response['HTTPcode'] = "N/A"

        except apiRequest.HTTPError as e:
            try:
                response['error'] = e.reason
                if not response['result']:
                    response['result'] = "error: %{0} for {1}".format(e.reason,defaultFQDN)
            except AttributeError:
                response['error'] = e
                if not response['result']:
                    response['result'] = "error: {0} for {1}".format(e,defaultFQDN)

    finish = time.time()
    response['responsetime'] = "%.3f" % (finish - start)
    return response

#if __name__ == "__main__":
#    main()

