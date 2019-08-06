#!/usr/bin/python
""" L3 FABRIC INBAND VLAN INTERFACE CREATE """
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
module: pn_l3_inband_vlan_interface
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to perform inband configurations for L3 fabric.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention.
    It performs following steps:
        - Assigns inband ip
        - Creates vRouters
        - Creates inband vlan
        - Creates inband vlan interfaces
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
    pn_csv_data:
      description:
        - String containing bgp as and switch name data parsed from csv file.
      required: True
      type: str
"""

EXAMPLES = """
- name: L3 fabric vrouter inband interface config
  pn_l3_inband_vlan_interface:
    pn_current_switch: "{{ inventory_hostname }}"
    pn_spine_list: "{{ groups['spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_inband_ipv4: "10.0.1.0/24"
    pn_csv_data: "{{ lookup('file', '{{ csv_file }}') }}".
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
            task='Fabric creation',
            msg='Fabric creation failed',
            changed=False
        )
    else:
        return 'Success'


def create_vlan(module):
    """
    Method to create vlans.
    :param module: The Ansible module to fetch input parameters.
    :param vlan_id: vlan id to be created.
    :param switch: Name of the switch on which vlan creation will be executed.
    :return: String describing if vlan got created or if it already exists.
    """
    vlan_id = module.params['pn_inband_vlan']
    current_switch = module.params['pn_current_switch']

    output = ''
    cli = pn_cli(module)
    clicopy = cli
    cli += ' vlan-show format id no-show-headers '
    existing_vlan_ids = run_cli(module, cli).split()
    existing_vlan_ids = list(set(existing_vlan_ids))

    if vlan_id not in existing_vlan_ids:
        cli = clicopy
        cli += ' vlan-create id %s scope local ' % vlan_id
        run_cli(module, cli)
        output += ' %s: Created vlan id %s' % (current_switch, vlan_id)
        output += ' with scope local \n'
    return output


def create_vrouter(module, csv_data):
    """
    Create a hardware vrouter.
    :param module: The Ansible module to fetch input parameters.
    :param csv_data: String containing vrouter data passed from csv file.
    :return: String describing if vrouter got created or not.
    """
    global CHANGED_FLAG
    output = ''
    clicopy = pn_cli(module)
    cli = clicopy

    current_switch = module.params['pn_current_switch']
    vrouter_name = current_switch + '-vrouter'
    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']

    cli = clicopy
    cli += ' vrouter-show format name no-show-headers'
    existing_vrouter_names = run_cli(module, cli)

    if existing_vrouter_names is not None:
        existing_vrouter_names = existing_vrouter_names.split()

    if vrouter_name not in existing_vrouter_names:
        csv_data = csv_data.splitlines()
        csv_data_list = [i.strip() for i in csv_data]

        # Parse csv file data and take the value of bgp_as for each switch.
        for row in csv_data_list:
            if not row or row.startswith('#'):
                continue
            else:
                row = row.strip()
                elements = row.split(',')
                elements = filter(None, elements)
                if current_switch in elements:
                    bgp_as = elements[-1]

        count = str(switch_list.index(current_switch) + 1)

        if current_switch in switch_list:
            router_id = count + '.' + count + '.' + count + '.' + count
            cli = clicopy
            cli += ' vrouter-create name %s fabric-comm bgp-as %s ' % (vrouter_name, bgp_as)
            cli += ' router-id %s bgp-redistribute connected' % router_id
            run_cli(module, cli)
            output = ' %s: Created vrouter with name %s \n' % (current_switch, vrouter_name)
            CHANGED_FLAG.append(True)

    return output


def assign_inband_ipv4(module):
    """
    Method to assign inband ip for switches.
    :param module: The Ansible module to fetch input parameters.
    :return: The output of run_cli() method.
    """
    global CHANGED_FLAG
    clicopy = pn_cli(module)
    inband_ip = module.params['pn_inband_ipv4']

    count = switch_list.index(current_switch)

    if inband_ip:
        inband_ip = inband_ip.split("/")
        start_ip = unicode(inband_ip[0], "utf-8")
        subnet_ipv4 = unicode(inband_ip[1], "utf-8")

    ips = finding_initial_ip(start_ip, subnet_ipv4, count)
    inband_ipv4 = str(ips[0]) + '/' + str(subnet_ipv4)

    # Get existing in-band ip.
    cli = clicopy
    cli += ' switch-setup-show format in-band-ip'
    existing_inband_ip = run_cli(module, cli).split()

    if inband_ipv4 not in existing_inband_ip:
        cli = clicopy
        cli += ' switch-setup-modify'
        cli += ' in-band-ip %s' % inband_ipv4
        run_cli(module, cli)
        CHANGED_FLAG.append(True)

    return '%s: Assigned in-band ip %s\n ' % (current_switch, inband_ipv4)


def inband_vlan_interface_add(module, vlan_id):
    """
    Method to add interface to particular vlan.
    :param module: The Ansible module to fetch input parameters.
    :param vlan_id: vlan_id on which interface to be created.
    :return: String describing if vrouter interface got added or not.
    """
    clicopy = pn_cli(module)
    vrouter_name = current_switch + '-vrouter'
    inband_ip = module.params['pn_inband_ipv4']

    if inband_ip:
        inband_ip = inband_ip.split("/")
        start_ip = unicode(inband_ip[0], "utf-8")
        subnet_ipv4 = unicode(inband_ip[1], "utf-8")
        count = switch_list.index(current_switch)

    ips = finding_initial_ip(start_ip, subnet_ipv4, count)
    ip = str(ips[1]) + '/' + str(subnet_ipv4)

    cli = clicopy
    cli += 'vrouter-interface-show vrouter-name %s ip %s ' % (vrouter_name, ip)
    cli += 'vlan %s format ip no-show-headers' % vlan_id
    existing_ip = run_cli(module, cli)

    if existing_ip:
        existing_ip = existing_ip.split()

    if ip not in existing_ip:
        cli = clicopy
        cli += 'vrouter-interface-add vrouter-name %s ip %s ' % (vrouter_name, ip)
        cli += 'vlan %s fabric-nic mtu 9216' % vlan_id
        run_cli(module, cli)
        CHANGED_FLAG.append(True)

    return "%s: Assigned interface ip %s to vlan %s\n " % (current_switch, ip, vlan_id)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list', default=[]),
            pn_leaf_list=dict(required=False, type='list', default=[]),
            pn_csv_data=dict(required=True, type='str'),
            pn_inband_ipv4=dict(required=False, type='str', default='192.16.0.1/24'),
            pn_inband_vlan=dict(required=False, type='str', default='4000'),
            pn_current_switch=dict(required=False, type='str'),

        )
    )

    global CHANGED_FLAG
    global switch_list
    global current_switch

    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']
    current_switch = module.params['pn_current_switch']
    vlan_id = module.params['pn_inband_vlan']

    output = ''
    output += assign_inband_ipv4(module)
    output += create_vlan(module)
    output += create_vrouter(module, module.params['pn_csv_data'])
    output += inband_vlan_interface_add(module, vlan_id)

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
        msg='vRouter creation and inband interface add succeeded',
        summary=results,
        exception='',
        task='vRouter creation and inband interface add',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )


if __name__ == '__main__':
    main()
