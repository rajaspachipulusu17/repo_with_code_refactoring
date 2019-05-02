#!/usr/bin/python
""" PN CLI subnet-create/modify/delete """

# Copyright 2018 Pluribus Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli


DOCUMENTATION = """
---
module: pn_subnet
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete subnet.
description:
  - C(create): create subnet
  - C(modify): modify subnet
  - C(delete): delete subnet
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - subnet configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_vnet:
    description:
      - VNET of the network
    required: false
    type: str
  pn_vrf:
    description:
      - vrf,subnet belongs to
    required: false
    type: str
  pn_anycast_gw_ip:
    description:
      - anycast gw-ip for the subnet
    required: false
    type: str
  pn_vlan:
    description:
      - VLAN
    required: false
    type: str
  pn_netmask:
    description:
      - ip subnet netmask
    required: false
    type: str
  pn_vxlan:
    description:
      - VXLAN VNID
    required: false
    type: str
  pn_network:
    description:
      - ip subnet network
    required: false
    type: str
  pn_scope:
    description:
      - scope of the subnet
    required: false
    choices: ['local', 'cluster', 'fabric']
  pn_name:
    description:
      - subnet name
    required: false
    type: str
"""

EXAMPLES = """
- name: create subnet
  pn_subnet:
    pn_action: 'create'
    pn_vxlan: '12000'
    pn_network: '172.1.1.0'
    pn_netmask: '24'
    pn_vrf: 'vrf-1'
    pn_anycast_gw_ip: '172.1.1.1'

- name: delete subnet
  pn_subnet:
    pn_action: 'delete'
    pn_name: 'subnet-vxlan-12000'

"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the subnet command.
  returned: always
  type: list
stderr:
  description: set of error responses from the subnet command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    action = module.params['pn_action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="Subnet %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="Subnet %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="Subnet %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'modify', 'delete']),
            pn_vnet=dict(required=False, type='str'),
            pn_vrf=dict(required=False, type='str'),
            pn_anycast_gw_ip=dict(required=False, type='str'),
            pn_vlan=dict(required=False, type='str'),
            pn_netmask=dict(required=False, type='str'),
            pn_vxlan=dict(required=False, type='str'),
            pn_network=dict(required=False, type='str'),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'cluster', 'fabric']),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    switch = module.params['pn_cliswitch']
    vnet = module.params['pn_vnet']
    vrf = module.params['pn_vrf']
    anycast_gw_ip = module.params['pn_anycast_gw_ip']
    vlan = module.params['pn_vlan']
    netmask = module.params['pn_netmask']
    vxlan = module.params['pn_vxlan']
    network = module.params['pn_network']
    scope = module.params['pn_scope']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += 'subnet-' + action
    if name:
        cli += ' name ' + name

    if action == 'create':
        if vlan:
            cli += ' vlan ' + vlan
        if vxlan:
            cli += ' vxlan ' + vxlan
        if vrf:    
            cli += ' vrf ' + vrf
        if network:
            cli += ' network ' + network
        if netmask:
            cli += ' netmask ' + netmask
        if anycast_gw_ip:
            cli += ' anycast-gw-ip ' + anycast_gw_ip

    if scope:
        cli += ' scope ' + scope

    if action in ['create', 'delete']:
        if vnet:
            cli += ' vnet ' + vnet

    run_cli(module, cli)

if __name__ == '__main__':
    main()
