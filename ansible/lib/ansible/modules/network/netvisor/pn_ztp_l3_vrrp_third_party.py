#!/usr/bin/python
""" PN CLI L3 VRRP THIRD PARTY """

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import *


DOCUMENTATION = """
---
module: pn_ztp_l3_vrrp
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: CLI command to configure VRRP - Layer 3 Setup
description: Virtual Router Redundancy Protocol (VRRP) - Layer 3 Setup
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
    pn_csv_data:
      description:
        - String containing vrrp data parsed from csv file.
      required: False
      type: str
"""

EXAMPLES = """
- name: Configure L3 VRRP
  pn_ztp_l3_vrrp:
    pn_spine_list: "{{ groups['third_party_spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_csv_data: "{{ lookup('file', '{{ csv_file }}') }}"
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


def configure_vrrp_for_non_clustered_switches(module, vlan_id, ip, ip_v6,
                                              non_cluster_leaf, CHANGED_FLAG, task, msg):
    """
    Method to configure VRRP for non clustered leafs.
    :param module: The Ansible module to fetch input parameters.
    :param vlan_id: vlan id to be assigned.
    :param ip: Ip address to be assigned.
    :param non_cluster_leaf: Name of non-clustered leaf switch.
    :return: Output string of configuration.
    """
    output = ''
    output, CHANGED_FLAG = create_vlan(module, vlan_id, non_cluster_leaf, CHANGED_FLAG, task, msg)
    output1, CHANGED_FLAG = configure_vrrp_for_non_cluster_leafs(module, ip, ip_v6, non_cluster_leaf,
                                                                 vlan_id, CHANGED_FLAG, task, msg)
    output += output1

    return output, CHANGED_FLAG


def configure_vrrp(module, csv_data, CHANGED_FLAG, task, msg):
    """
    Method to configure VRRP L3.
    :param module: The Ansible module to fetch input parameters.
    :param csv_data: String containing vrrp data passed from csv file.
    :return: Output string of configuration.
    """
    output = ''
    vrrp_ipv6 = ''
    vrrp_ip = ''
    addr_type = module.params['pn_addr_type']

    csv_data = csv_data.splitlines()
    csv_data_list = [i.strip() for i in csv_data]
    # Parse csv file data and configure VRRP.
    for row in csv_data_list:
        if not row or row.startswith('#'):
            continue
        else:
            row = row.strip()
            elements = row.split(',')
            elements = filter(None, elements)
            if any(field.strip() for field in row):
                vlan_id = elements.pop(0).strip()
            else:
                continue
            switch_list = []
            if addr_type == 'ipv4_ipv6' or addr_type == 'ipv4':
                vrrp_ip = elements.pop(0).strip()
            if addr_type == 'ipv4_ipv6' or addr_type == 'ipv6':
                vrrp_ipv6 = elements.pop(0).strip()
            leaf_switch_1 = elements.pop(0).strip()
            if module.params['pn_current_switch'] == leaf_switch_1:
                if len(elements) > 2:
                    leaf_switch_2 = elements.pop(0).strip()
                    vrrp_id = elements.pop(0).strip()
                    active_switch = elements.pop(0).strip()
                    switch_list.append(leaf_switch_1)
                    switch_list.append(leaf_switch_2)
                    mod = 'l3-vrrp'
                    output, CHANGED_FLAG = configure_vrrp_for_clustered_switches(
                        module,
                        vrrp_id,
                        vrrp_ip,
                        vrrp_ipv6,
                        active_switch,
                        vlan_id,
                        switch_list, mod, CHANGED_FLAG, task, msg)
                else:
                    result, CHANGED_FLAG = configure_vrrp_for_non_clustered_switches(
                            module, vlan_id, vrrp_ip, vrrp_ipv6, leaf_switch_1,
                            CHANGED_FLAG, task, msg)
                    output += result
    return CHANGED_FLAG, output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_csv_data=dict(required=True, type='str'),
            pn_current_switch=dict(required=True, type='str'),
            pn_pim_ssm=dict(required=False, type='bool', default=False),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
            pn_ospf_area_id=dict(required=False, type='str', default='0'),
            pn_addr_type=dict(required=False, type='str',
                              choices=['ipv4', 'ipv6', 'ipv4_ipv6'],
                              default='ipv4'),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Configure L3 vrrp third party',
    msg = 'L3 vrrp configuration failed'

    leaf_list = module.params['pn_leaf_list']

    if module.params['pn_current_switch'] in leaf_list:
        CHANGED_FLAG, message = configure_vrrp(module, module.params['pn_csv_data'], CHANGED_FLAG, task, msg)

    # Exit the module and return the required JSON.
    message_string = message
    results = []
    switch_list = module.params['pn_spine_list'] + leaf_list
    for switch in switch_list:
        replace_string = switch + ': '

        for line in message_string.splitlines():
            if replace_string in line:
                json_msg = {
                    'switch': switch,
                    'output': (line.replace(replace_string, '')).strip()
                }
                results.append(json_msg)

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        task='Configure L3 vrrp',
        msg='L3 third party vrrp configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )


if __name__ == '__main__':
    main()
