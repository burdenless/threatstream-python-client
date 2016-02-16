#!/usr/bin/env python
# threatstreap-api.py
#
# Copyright (C) 2014 THREAT STREAM, Inc.
# This file is subject to the terms and conditions of the GNU General Public
# License version 2.  See the file COPYING in the main directory for more
# details.

import requests
from re import match
from sys import exit, argv, stderr

__version__ = 2
__author__ = 'ThreatStream LABS - NMA - byt3smith'


class ThreatStreamApi():
    def __init__(self):
        self.apikey = ''
        self.apiuser = ''
        self.url = 'https://api.threatstream.com/api/v1'
        self.tags = 'testing,api'


    def process_request(self, request_data):
        try:
            print '\n[*] Headers:'
            for i in request_data.headers:
                print i + ': ' + request_data.headers[i]
            print "\n[*] Request:"
            for i in request_data.request.headers:
                print i + ': ' + request_data.request.headers[i]
            print "\n"

            success = '[+] %s has been submitted for analysis!' % item
            print 'HTTP Status code: {}'.format(request_data.status_code)
            if request_data.status_code == 202:
                return(request_data.text + "\n" + success) # Return response
            elif request_data.status_code == 401:
                print 'Access Denied. Check API Credentials'
                exit(0)
            else: print 'API Connection Failure.'

        except Exception as err:
            print 'API Access Error: {}'.format(err)
            exit(0)

        return request_data


    def submit_url(self, item):
        url = '{}/submit/new/?username={}&api_key={}'.format(self.url, self.apiuser, self.apikey)

        params = {
            "report_radio-classification":"private",
            "report_radio-platform":"WINDOWS7",
            "report_form_submit":"Send",
            "report_radio-notes":"Uploaded URL",
            "report_radio-url":item
        } # HTTP POST parameters

        # Build and send the HTTP request
        http_req = requests.post(url, data=params)
        self.process_request(http_req)

    def submit_file(self, item):
        url = '{}/submit/new/?username={}&api_key={}'.format(self.url, self.apiuser, self.apikey)

        params = {
            "report_radio-classification":"private",
            "report_radio-platform":"WINDOWS7",
            "report_form_submit":"Send",
            "report_radio-notes":"Uploaded sample"
        } # HTTP POST parameters

        file_struct = {'report_radio-file': open(item, 'rb')}
        # Build and send the HTTP request
        http_req = requests.post(url, data=params, files=file_struct)
        self.process_request(http_req)


if __name__ == '__main__':
    arglen = len(argv)
    usage = "\nUsage: %s <file/url> <username> <API key> {malware tags}" % __file__
    if arglen < 4:
        print usage
        exit(0)

    ts = ThreatStreamApi()
    item = argv[1]
    ts.apiuser = argv[2]
    ts.apikey = argv[3]
    if len(argv) == 5:
        ts.tags = argv[4]
    matches = match("((?:http|ftp|https)\:\/\/(?:[\w+?\.\w+])+[a-zA-Z0-9\~\!\@\#\$\%\^\&\*\(\)_\-\=\+\\\/\?\.\:\;]+)", item)
    if matches:
        sample_type = 'URL'
        print "Submitting as: [ %s ]" % sample_type
        response = ts.submit_url(item)
    else:
        sample_type = 'File'
        print "Submitting as [ %s ]" % sample_type
        response = ts.submit_file(item)
    print response
