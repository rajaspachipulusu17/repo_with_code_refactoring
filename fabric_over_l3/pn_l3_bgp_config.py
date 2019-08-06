#!/usr/bin/python
""" L3 FABRIC BGP CONFIG """
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
from ansible.module_utils.pn_nvos import BetterIPv4Network, finding_initial_ip


DOCUMENTATION = """
---
module: pn_l3_bgp_config
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to perform bgp configurations for L3 fabric.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention.
    It performs following steps:
        - Creates L3 interfaces
        - Adds L3 interfaces to BGP
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
    pn_ipv4_start_address:
      description:
        - Specify network address to be used in configuring link IPv4 address for layer3.
      required: False
      type: str
    pn_csv_data:
      description:
        - String containing bgp as and switch name data parsed from csv file.
      required: True
      type: str
"""

EXAMPLES = """
- name: Zero Touch Provisioning - Layer3 setup
  pn_ztp_l3_links:
    pn_net_address_ipv4: '100.100.1.0/24'
    pn_current_switch: "{{ inventory_hostname }}"
    pn_spine_list: "{{ groups['spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
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
            task='BGP config',
            msg='BGP config failed',
            changed=False
        )
    else:
        return 'Success'


def bgp_config(module, csv_data):
    """
    Create a hardware vrouter.
    :param module: The Ansible module to fetch input parameters.
    :param csv_data: String containing vrouter data passed from csv file.
    :return: String describing if bgp config succeed or not.
    """
    global CHANGED_FLAG
    output = ''
    clicopy = pn_cli(module)
    cli = clicopy

    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    start_addr_ip = module.params['pn_ipv4_start_address']
    vrouter_name = current_switch + '-vrouter'

    csv_data = csv_data.splitlines()
    csv_data_list = [i.strip() for i in csv_data]

    for count in range(len(leaf_list)):
        if current_switch in spine_list:
            cli = clicopy
            cli += ' lldp-show sys-name %s format' % (leaf_list[count])
            cli += ' local-port no-show-headers'
            l3_port = run_cli(module, cli)

            if l3_port:
                l3_port = l3_port.strip().split()
                l3_port = list(set(l3_port))

            if start_addr_ip:
                start_addr_ip_1 = start_addr_ip.split("/")
                start_ip = unicode(start_addr_ip_1[0], "utf-8")
                subnet_ipv4 = unicode(start_addr_ip_1[1], "utf-8")

                ip_cal_itr = (switch_list.index(leaf_list[count]) - 2) + (switch_list.index(current_switch) * 10)
                ips = finding_initial_ip(start_ip, subnet_ipv4, ip_cal_itr)
                start_addr_ipv4 = str(ips[0]) + '/' + str(subnet_ipv4)

                cli = clicopy
                cli += ' vrouter-interface-show vrouter-name %s' % vrouter_name
                cli += ' l3-port %s ip %s ' % (l3_port[0], start_addr_ipv4)
                cli += ' format ip no-show-headers'
                existing_ip = run_cli(module, cli)

                if existing_ip:
                    existing_ip = existing_ip.split()

                if start_addr_ipv4 not in existing_ip:
                    cli = clicopy
                    cli += 'vrouter-interface-add vrouter-name %s ' % vrouter_name
                    cli += 'l3-port %s ip %s mtu 9216 ' % (l3_port[0], start_addr_ipv4)
                    run_cli(module, cli)
                    CHANGED_FLAG.append(True)
                    output += '%s: Added vrouter interface with ip %s on %s\n ' % (current_switch, start_addr_ipv4, vrouter_name)

                # Adding vRouter L3 interface to bgp neighor.
                for row in csv_data_list:
                    if not row or row.startswith('#'):
                        continue
                    else:
                        row = row.strip()
                        elements = row.split(',')
                        elements = filter(None, elements)
                        if leaf_list[count] in elements:
                            remote_as = elements[-1]

                cli = clicopy
                cli += ' vrouter-bgp-show vrouter-name %s' % vrouter_name
                cli += ' neighbor %s format neighbor no-show-headers' % ips[1]
                neighbor = run_cli(module, cli)
                if neighbor:
                    neighbor = neighbor.split()

                if str(ips[1]) not in neighbor:
                    cli = clicopy
                    cli += ' vrouter-bgp-add vrouter-name %s' % vrouter_name
                    cli += ' neighbor %s remote-as %s ' % (ips[1], remote_as)
                    run_cli(module, cli)
                    CHANGED_FLAG.append(True)
                    output += '%s:  Added BGP Neighbor %s for %s \n' % (current_switch, ips[1], vrouter_name)

    for count in range(len(spine_list)):
        if current_switch in leaf_list:
            cli = clicopy
            cli += ' lldp-show sys-name %s format local-port no-show-headers' % (spine_list[count])
            l3_port = run_cli(module, cli)

            if l3_port:
                l3_port = l3_port.strip().split()
                l3_port = list(set(l3_port))

            if start_addr_ip:
                start_addr_ip_1 = start_addr_ip.split("/")
                start_ip = unicode(start_addr_ip_1[0], "utf-8")
                subnet_ipv4 = unicode(start_addr_ip_1[1], "utf-8")

                ip_cal_itr = (switch_list.index(spine_list[count]) * 10) + (switch_list.index(current_switch) - 2)
                ips = finding_initial_ip(start_ip, subnet_ipv4, ip_cal_itr)
                start_addr_ipv4 = str(ips[1]) + '/' + str(subnet_ipv4)

                cli = clicopy
                cli += 'vrouter-interface-show vrouter-name %s l3-port %s' % (vrouter_name, l3_port[0])
                cli += ' ip %s format ip no-show-headers' % start_addr_ipv4
                existing_ip = run_cli(module, cli)

                if existing_ip:
                    existing_ip = existing_ip.split()

                if start_addr_ipv4 not in existing_ip:
                    cli = clicopy
                    cli += 'vrouter-interface-add vrouter-name %s ' % vrouter_name
                    cli += 'l3-port %s ip %s mtu 9216' % (l3_port[0], start_addr_ipv4)
                    run_cli(module, cli)
                    CHANGED_FLAG.append(True)
                    output += '%s: Added vrouter interface with ip %s on %s\n ' % (current_switch, start_addr_ipv4, vrouter_name)

                for row in csv_data_list:
                    if not row or row.startswith('#'):
                        continue
                    else:
                        row = row.strip()
                        elements = row.split(',')
                        elements = filter(None, elements)
                        if spine_list[count] in elements:
                            remote_as = elements[-1]

                cli = clicopy
                cli += ' vrouter-bgp-show vrouter-name %s' % vrouter_name
                cli += ' neighbor %s format neighbor no-show-headers' % ips[0]
                neighbor = run_cli(module, cli)
                if neighbor:
                    neighbor = neighbor.split()

                if str(ips[0]) not in neighbor:
                    cli = clicopy
                    cli += ' vrouter-bgp-add vrouter-name %s' % vrouter_name
                    cli += ' neighbor %s remote-as %s allowas-in' % (ips[0], remote_as)
                    run_cli(module, cli)
                    CHANGED_FLAG.append(True)
                    output += '%s:  Added BGP Neighbor %s for %s \n' % (current_switch, ips[0], vrouter_name)

    return output


def main():

    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list', default=[]),
            pn_leaf_list=dict(required=False, type='list', default=[]),
            pn_ipv4_start_address=dict(required=False, type='str', default='172.168.1.1'),
            pn_current_switch=dict(required=False, type='str'),
            pn_csv_data=dict(required=True, type='str'),


        )
    )

    global CHANGED_FLAG
    global switch_list
    global current_switch

    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']
    current_switch = module.params['pn_current_switch']

    output = ''
    output += bgp_config(module, module.params['pn_csv_data'])

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
        msg='L3 BGP configuration succeeded',
        summary=results,
        exception='',
        task='BGP configurations',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )


if __name__ == '__main__':
    main()
