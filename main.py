#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2023/7/7 16:24
# @Author  : Ma JiaWei
# @Email   : 310916789@qq.com
# @File    : main.py
# @Software: PyCharm

import os
import re
import tldextract
import requests
import json
import logging
from kubernetes import config, client


def get_token(username, password):
    url = 'https://{}/api/login'.format(os.getenv('DOMAIN_ADMIN_HOST'))
    data = {
        'username': username,
        'password': password
    }
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url=url, headers=headers, data=json.dumps(data))
        result = json.loads(response.text)
        if result['code'] == 0:
            token = result['data']['token']
            return token
        else:
            logging.info(response.text)
            return False
    except Exception as e:
        logging.error(e)


def add_domain(token, domain):
    url = 'https://{}/api/addDomainInfo'.format(os.getenv('DOMAIN_ADMIN_HOST'))
    data = {
        'domain': domain
    }
    headers = {
        'Content-Type': 'application/json',
        'X-Token': token
    }
    try:
        response = requests.post(url=url, headers=headers, data=json.dumps(data))
        result = json.loads(response.text)
        if result['code'] == 0:
            return True
        else:
            logging.error(response.text)
            return False
    except Exception as e:
        logging.error(e)


def get_domain_list(token):
    url = 'https://{}/api/getDomainInfoList'.format(os.getenv('DOMAIN_ADMIN_HOST'))
    data = {
        'page': 1,
        'size': 100
    }
    headers = {
        'Content-Type': 'application/json',
        'X-Token': token
    }
    _list = []
    try:
        while True:
            response = requests.post(url=url, headers=headers, data=json.dumps(data))
            result = json.loads(response.text)
            if result['code'] == 0:
                total = int(result['data']['total'])
                if data['page'] * data['size'] > total:
                    break
                else:
                    _list += result['data']['list']
                    data['page'] += 1
            else:
                logging.error(response.text)

        return _list
    except Exception as e:
        logging.error(e)


def add_group(token, name):
    url = 'https://{}/api/addGroup'.format(os.getenv('DOMAIN_ADMIN_HOST'))
    data = {
        'name': name
    }
    headers = {
        'Content-Type': 'application/json',
        'X-Token': token
    }
    try:
        response = requests.post(url=url, headers=headers, data=json.dumps(data))
        result = json.loads(response.text)
        if result['code'] == 0:
            return result['data']
        else:
            logging.error(response.text)
            return False
    except Exception as e:
        logging.error(e)


def get_group_by_name(token, name):
    url = 'https://{}/api/getGroupList'.format(os.getenv('DOMAIN_ADMIN_HOST'))
    data = {
        'keyword': name
    }
    headers = {
        'Content-Type': 'application/json',
        'X-Token': token
    }
    try:
        response = requests.post(url=url, headers=headers, data=json.dumps(data))
        result = json.loads(response.text)
        if result['code'] == 0:
            return result['data']['list']
        else:
            logging.error(response.text)
            return None
    except Exception as e:
        logging.error(e)


def main():
    token = get_token(username=os.getenv('DOMAIN_ADMIN_USERNAME'), password=os.getenv('DOMAIN_ADMIN_PASSWORD'))
    domain_list = [item['domain'] for item in get_domain_list(token=token)]
    config.load_kube_config()
    kube_api = client.ExtensionsV1beta1Api()
    ingresses = kube_api.list_ingress_for_all_namespaces()
    domains = set()
    for item in ingresses.items:
        if 'NAMESPACE_MATCH' in os.environ and not re.search(os.getenv('NAMESPACE_MATCH'), item.metadata.namespace):
            continue
        if 'NAMESPACE_NOT_MATCH' in os.environ and re.search(os.getenv('NAMESPACE_NOT_MATCH'), item.metadata.namespace):
            continue
        for rule in item.spec.rules:
            domain = tldextract.extract(rule.host).registered_domain
            domains.add(domain)
    for item in domains:
        if item not in domain_list:
            add_domain(token=token, domain=item)


if __name__ == '__main__':
    main()
