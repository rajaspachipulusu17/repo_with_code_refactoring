#!/usr/bin/python
""" PN L3 FABRIC JOIN TO INBAND NETWORK """
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
module: pn_fabric_join_with_inband
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to perform inband configurations for L3 fabric.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention.
    It performs following steps:
        - Adds switch routes on each switch for routing
        - Joins fabric with seed switch inband ip
options:
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
    pn_inband_vlan:
    description:
      - Specify a VLAN identifier for the VLAN. This is a value between
        2 and 4092.
      required: False
      default: 4000
      type: str
"""

EXAMPLE = """
- name: Joins fabric and add switch routes
  pn_fabric_join_with_inband:
    pn_current_switch: "{{ inventory_hostname }}"
    pn_spine_list: "{{ groups['spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_inband_ipv4: "10.0.1.0/24"
    pn_inband_vlan: '4000'
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
            task='Fabric join to inband network',
            msg='Fabric join to inband network failed',
            changed=False
        )
    else:
        return 'Success'


def switch_route(module):
    """
    Method to create fabric and fabric inband network.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing if fabric is joined to inband network or not.
    """
    output = ''
    clicopy = pn_cli(module)
    cli = clicopy

    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    current_switch = module.params['pn_current_switch']
    inband_network = module.params['pn_inband_ipv4']
    vrouter_name = current_switch + '-vrouter'
    vlan_id = module.params['pn_inband_vlan']

    inband = inband_network.split('/')[0]
    inband = inband.split(".")
    last_octat = str(int(inband[3]) + 1)
    inband[3] = last_octat

    inband_ip = '.'.join(inband)

    if current_switch != spine_list[0]:
        cli = clicopy
        cli += 'switch-route-show format network no-show-headers'
        existing_network = run_cli(module, cli).split()

        if inband_network not in existing_network:
            cli = clicopy
            cli += 'vrouter-interface-show vrouter-name %s vlan %s ' % (vrouter_name, vlan_id)
            cli += 'format ip no-show-headers'
            out = run_cli(module, cli)
            if out:
                out = out.split()

            interface = out[1]

            cli = clicopy
            cli += ' switch-route-create network %s gateway-ip %s' % (inband_network, interface.split('/')[0])
            run_cli(module, cli)
            CHANGED_FLAG.append(True)
            output += '%s: Added network %s with gateway %s\n' % (current_switch, inband_network, interface.split('/')[0])

        cli = clicopy
        cli += ' fabric-info'
        cli = shlex.split(cli)
        rc, out, err = module.run_command(cli)

        if err:
            cli = clicopy
            cli += ' fabric-join switch-ip %s ' % (inband_ip)
            run_cli(module, cli)
            CHANGED_FLAG.append(True)
            output += '%s: Joined switch ip %s\n' % (current_switch, inband_ip)

    return output


def main():

    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list', default=[]),
            pn_leaf_list=dict(required=False, type='list', default=[]),
            pn_inband_ipv4=dict(required=False, type='str', default='192.168.0.1/24'),
            pn_current_switch=dict(required=False, type='str'),
            pn_inband_vlan=dict(required=False, type='str', default='4000'),
        )
    )

    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']
    output = ''
    output += switch_route(module)

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
        msg='Fabric join with inband ip succeeded',
        summary=results,
        exception='',
        task='Fabric join to inband network',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )


if __name__ == '__main__':
    main()
