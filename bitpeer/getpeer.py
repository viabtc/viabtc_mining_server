#!/usr/bin/python
# -*- coding: utf-8 -*-

import time
import json
import requests

country_list = ['CN']
region_list = ['']

offset = 0
limit  = 500

def main():
    peers = []
    r = requests.get('https://bitnodes.21.co/api/v1/snapshots/latest/', verify=False)
    nodes = r.json()['nodes']
    index = 0
    for addr in nodes:
        if '[' in addr:
            continue
        country = nodes[addr][7]
        if not country:
            continue
        city = nodes[addr][10]
        if not city:
            continue
        region = city.split('/')[0]
        if country_list:
            if country in country_list:
                index += 1
                if index > offset and index <= offset + limit:
                    peers.append(addr)
        else:
            if region in region_list:
                index += 1
                if index > offset and index <= offset + limit:
                    peers.append(addr)

    info = {'peers': peers}
    print(json.dumps(info, indent=4))

if __name__ == '__main__':
    main()

