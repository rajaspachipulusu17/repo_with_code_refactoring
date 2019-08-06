#!/usr/bin/python
""" PN L3 CREATE FABRIC AND INBAND NETWORK """
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

import shlex
import ipaddress
import itertools as it
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli, BetterIPv4Network, finding_initial_ip


DOCUMENTATION = """
---
module: pn_l3_fabric_and_inband_network
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to perform bgp configurations for L3 fabric.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention.
    It performs following steps:
        - Creates L3 fabric
        - Adds inband network ranges to seed switch
options:
    pn_fabric_name:
      description:
        - Specify name of the fabric.
      required: True
      type: str
    pn_spine_list:
      description:
        - Specify list of Spine hosts
      required: False
      type: list
    pn_leaf_list:
      description:
        - Specify list of leaf hosts
      required: False
      type: list
    pn_current_switch:
      description:
        - Name of the switch on which this task is currently getting executed.
      required: False
      type: str
    pn_inband_ipv4:
      description:
        - Inband ips to be assigned to switches starting with this value.
      required: False
      default: 192.168.0.1/24.
      type: str
"""

EXAMPLE = """
- name: Creates fabric and inband network on seed switch
  pn_l3_fabric_and_inband_network:
    pn_fabric_name: "sample-fabric"
    pn_current_switch: "{{ inventory_hostname }}"
    pn_spine_list: "{{ groups['spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_inband_ipv4: "10.0.1.0/24"
"""

RETURN = """
summary:
  description: It contains output of each configuration along with switch name.
  returned: always
  type: str
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
unreachable:
  description: Indicates whether switch was unreachable to connect.
  returned: always
  type: bool
failed:
  description: Indicates whether or not the execution failed on the target.
  returned: always
  type: bool
exception:
  description: Describes error/exception occurred while executing CLI command.
  returned: always
  type: str
task:
  description: Name of the task getting executed on switch.
  returned: always
  type: str
msg:
  description: Indicates whether configuration made was successful or failed.
  returned: always
  type: str
"""

CHANGED_FLAG = []


def run_cli(module, cli):
    """
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    results = []
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    if out:
        return out
    if err:
        json_msg = {
            'switch': module.params['pn_current_switch'],
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception=err.strip(),
            summary=results,
            task='Create fabric and inband network',
            msg='Create fabric and inband network failed',
            changed=False
        )
    else:
        return 'Success'


def create_fabric_and_inband_network(module):
    """
    Method to create fabric and fabric inband network.
    :param module: The Ansible module to fetch input parameters.
    """
    output = ''
    clicopy = pn_cli(module)
    cli = clicopy

    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']
    current_switch = module.params['pn_current_switch']
    inband_network = module.params['pn_inband_ipv4']
    fabric_name = module.params['pn_fabric_name']

    for switch in switch_list:
        inband_network_1 = inband_network.split("/")
        start_ip = unicode(inband_network_1[0], "utf-8")
        subnet_ipv4 = unicode(inband_network_1[1], "utf-8")
        count = switch_list.index(switch)

        if switch_list.index(switch) == 0:
            cli = clicopy
            cli += ' fabric-show format name no-show-headers '
            existing_fabrics = run_cli(module, cli).split()

            if fabric_name not in existing_fabrics:
                cli = clicopy
                cli += 'fabric-create name %s fabric-network in-band control-network in-band' % fabric_name
                out = run_cli(module, cli)
                if 'created' in out:
                    CHANGED_FLAG.append(True)
                    output += '%s: fabric with name %s created\n' % (switch, fabric_name)

        if switch_list.index(switch) != 0:
            this_network = finding_initial_ip(start_ip, subnet_ipv4, count, in_band_network=True)

            cli = clicopy
            cli += 'fabric-in-band-network-show format network no-show-headers'
            existing_networks = run_cli(module, cli)

            if existing_networks:
                existing_networks = existing_networks.split()

            if str(this_network) not in existing_networks:
                cli = clicopy
                cli += 'fabric-in-band-network-create network %s' % this_network
                run_cli(module, cli)
                CHANGED_FLAG.append(True)

            output += '%s: Added inband network %s\n' % (switch, this_network)

    return output


def main():

    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list', default=[]),
            pn_leaf_list=dict(required=False, type='list', default=[]),
            pn_inband_ipv4=dict(required=False, type='str'),
            pn_current_switch=dict(required=False, type='str'),
            pn_fabric_name=dict(required=True, type='str'),
        )
    )

    output = ''
    output += create_fabric_and_inband_network(module)

    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']
    # Exit the module and return the required JSON.
    message_string = output
    results = []
    for switch in switch_list:
        replace_string = switch + ': '

        for line in message_string.splitlines():
            if replace_string in line:
                json_msg = {
                    'switch': switch,
                    'output': (line.replace(replace_string, '')).strip()
                }
                results.append(json_msg)

    module.exit_json(
        unreachable=False,
        msg='Create fabric and inband network succeeded',
        summary=results,
        exception='',
        task='Create fabric and inband network',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )


if __name__ == '__main__':
    main()
