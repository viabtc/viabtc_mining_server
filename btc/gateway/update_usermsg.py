#!/usr/bin/python
# -*- coding: utf-8 -*-

import time
import json
import requests
import os
import sys

def main():
    if len(sys.argv) < 3 :
        print 'no api or file specified'
        sys.exit()
    api = sys.argv[1]
    file_path = sys.argv[2]

    r = requests.get(api, headers={"Authorization": "ac8c55f83a2eab9bb922c242d6fac125941f67e8911557f2"}, verify=False)
    data = r.json()

    if data.has_key('error') == False:
        print 'false'
        sys.exit()
    if data['error']['message'] != 'ok':
        print 'false'
        sys.exit()
    if data.has_key('result') == False:
        print 'false'
        sys.exit()

    fp = open(file_path, "w+")
    json.dump(data['result'], fp, indent=4)
    print 'true'

if __name__ == '__main__':
    main()