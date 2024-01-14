#!/usr/bin/env python

#
# Filename    : infoblox.py
# Date        : 20 Mar 2018
# Author      : Balaji Venkataraman (xbalaji@gmail.com)
# Description : minimal infoblox module for ansible, see the original 
#               python implementation (infoBloxUtils.py) for additional 
#               functionality
#
# Usage:
# To be used by ansible playbook, example usage, see "test-iblox.yml",
# typically used as below:
#   ansible-playbook -M . test-iblox.yml
# 

ANSIBLE_METADATA = {
  'metadata_version': '0.1',
  'status': ['preview'],
  'supported_by': 'xbalaji@gmail.com'
}

DOCUMENTATION = '''
---
module: infoblox
author: "Balaji Venkataraman (xbalaji@gmail.com)"
short_description: Simple Infoblox management using web API
description:
  - Minimal Infoblox utility to create, delete host records using web API
version_added: "1.0"
requirements:
  - "requests >= 2.18.4"
  - "json >= 2.0.9"
options:
  server:
    description: Infoblox IP/URL
    required: True
  username:
    description: Infoblox username with WAPI rights
    required: True
  password:
    description: Password associated with the username
    required: True
  network:
    description:
      - Network address
      - Only CIDR format supported
    required: True
  hosts:
    description: 
      - Hostname list to create or remove records
      - Hostname must be in fqdn format, otherwise domain needs to be specified
    required: False
  domain:
    description: Domain name for the hosts
    required: False
  state:
    description:
      - whether to query, create, remove host records
      - valid values (present, removed, list)
    required: True
  numip:
    description: Get the number of next available free IP addresses
    required: False
'''

EXAMPLES = '''
---
- hosts: localhost
  connection: local
  gather_facts: False

  tasks:
  - name: add three hosts
    infoblox:
      server:   iblox.lab.mycompany.com
      username: wapiuser
      password: wapipass
      network:  10.20.31.32/27
      hosts: ["dcos-master-01", "dcos-master-02", "dcos-master-03" ]
      domain: lab.mycompany.com
      state: present
    register: infoblox
'''

RETURN = '''
  result:
    description: result returned by the module
    returned: success
    type: list
    sample: [ 
      { "ip": "10.20.31.52", "host": "dcos-master-01.lab.orgname.com" },
      { "ip": "10.20.31.54", "host": "dcos-master-02.lab.orgname.com" },
      { "ip": "10.20.31.55", "host": "dcos-master-03.lab.orgname.com" }
    ]

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.utils.display import Display

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


WAPI_VER="wapi/v2.7"

display = Display()

#---------------------------------------------------------------------
# infoblox - class begin
#---------------------------------------------------------------------
class InfoBloxIPAM(object):
  def __init__(self, desc, host, name, pswd, nets = []):
    self.desc = desc
    self.host = host
    self.name = name
    self.pswd = pswd
    self.nets = []
    self.wapi = "wapi/v2.7"
    self.auth = (self.name, self.pswd)
    self.base_url = "https://{}/{}".format(self.host,self.wapi)
    if nets and len(nets) > 0:
      self.add_networks(nets)
    return

  def __repr__(self):
    rstr  = "Description: {}\n".format(self.desc)
    rstr += "Host: {}, API verison: {}\n".format(self.host, self.wapi)
    rstr += "Name: {}, Password: {}\n".format(self.name, self.pswd)
    rstr += "Configured networks:\n"
    if len(self.nets):
      for net in self.nets:
        rstr += "\t{}: {}\n".format(net["net"], net["ref"])
    else:
        rstr += "\tNone\n"
    return rstr

  def add_networks(self, networks):
    if networks and len(networks) > 0:
      for ix in networks:
        # get the reference to the network from IPAM
        req_url = "{}/network?network={}".format(self.base_url, ix)
        requests.packages.urllib3.disable_warnings()
        response = requests.get(req_url, auth=self.auth, verify=False)
        ref = response.json()[0]["_ref"]
        self.nets.append({"net": ix, "ref": ref})
    return

  def next_freeip(self, network_id = "", num_ips = 1):
    # return the next freeip from the network, if no network_id 
    # is given, get the next freeip from all known networks
    ret_ip = list()
    for network in self.nets:
      net = network["net"]
      ref = network["ref"]
      if network_id and net != network_id: continue
      req_url = "{}/{}?_function=next_available_ip&num={}".format(self.base_url, ref, num_ips)
      requests.packages.urllib3.disable_warnings()
      response = requests.post(req_url, auth=self.auth, verify=False)
      if response.status_code == requests.codes.ok:
        ret_ip.append({net : response.json()["ips"]})
    return ret_ip

  def create_hosts(self, hosts):
    ret_list = list()
    url = "{}/record:host".format(self.base_url)
    headers = { 'accept': "application/json" }

    ipv4block = list()
    for net in self.nets:
      ipv4block.append(dict({"ipv4addr": "func:nextavailableip:{}".format(net["net"])}))

    for host in hosts:
      payload = json.dumps(dict({"name": host, "ipv4addrs": ipv4block}))
      requests.packages.urllib3.disable_warnings()
      response = requests.post(url, auth=self.auth, data=payload, headers=headers, verify=False)
      if response.status_code == requests.codes.created:
        # returns the host record, now query the created host record, use it and find it details
        url = "{}/{}".format(self.base_url, response.json())
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, auth=self.auth, verify=False)
        # extract the hostname and ip address, save it to return dict
        ip = response.json()["ipv4addrs"][0]["ipv4addr"]
        ret_list.append({"host": host, "ip": ip})
      else:
        return dict({ "failed_status_code": response.status_code})
    return ret_list

  def remove_hosts(self, hosts):
    deleted_hosts = list()
    for host in hosts:
      url = "{}/record:host?name={}".format(self.base_url, host)
      requests.packages.urllib3.disable_warnings()
      response = requests.get(url, auth=self.auth, verify=False)
      if response.status_code == requests.codes.ok and response.json():
        ref = response.json()[0]["_ref"]
        url = "{}/{}".format(self.base_url, ref)
        requests.packages.urllib3.disable_warnings()
        response = requests.delete(url, auth=self.auth, verify=False)
        if response.status_code == requests.codes.ok:
          deleted_hosts.append(host)
    # end of for loop
    return deleted_hosts
 
#---------------------------------------------------------------------
# infoblox - class end
#---------------------------------------------------------------------

def main():
  ''' main module to invoke Infoblox web api '''
  infoblox_args = dict(
    server=dict(required=True, type='str'),
    username=dict(required=True, type='str'),
    password=dict(required=True, type='str', no_log=True),
    network=dict(required=True, type='str'),
    hosts=dict(required=False, type='list'),
    domain=dict(required=False, type='str'),
    state=dict(required=True, type='str'),
    numip=dict(required=False, type='int'),
  ) 
  module = AnsibleModule(argument_spec=infoblox_args, supports_check_mode=False)

  """ make the variables available to rest of this function """
  server   = module.params["server"]
  username = module.params["username"]
  password = module.params["password"]
  network  = [ module.params["network"] ]
  hosts    = module.params["hosts"]
  domain   = module.params["domain"]
  state    = module.params["state"].lower()
  numip    = module.params["numip"]

  iblox = InfoBloxIPAM('ansible infoblox', server, username, password, network)
  display.debug(iblox)
  display.vv(iblox)

  if numip > 0:
    if state in ["list", "getip", "query"]:
      result = iblox.next_freeip(num_ips = numip)
    else:
      result = dict(failed=True, msg="state invalid for numip")
  elif len(hosts):
    if domain:
      hosts = [ "{}.{}".format(host.lower(), domain.lower()) for host in hosts ]
    if state in ["present", "installed", "latest"]:
      result = iblox.create_hosts(hosts)
    elif state in ["absent", "removed"]:
      result = iblox.remove_hosts(hosts)
    else:
      result = dict(failed=True, msg="invalid state ({}) for add or remove".format(state))
  else:
    result = dict(failed=True, msg="invalid operation requested")
  module.exit_json(changed=True, result=result)

if __name__ == "__main__":
  main()

