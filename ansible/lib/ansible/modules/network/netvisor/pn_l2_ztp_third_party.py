#!/usr/bin/python
""" PN CLI L2 with third party spine switches """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, run_command, modify_stp
from ansible.module_utils.network.netvisor.pn_netvisor import create_vlag, create_trunk, get_ports
from ansible.module_utils.network.netvisor.pn_netvisor import create_cluster, find_non_clustered_leafs
from ansible.module_utils.network.netvisor.pn_netvisor import update_fabric_network_to_inband


DOCUMENTATION = """
---
module: pn_l2_third_party
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: CLI command to configure L2 with 3rd party spine switches.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention. This module will
    configure trunks, vlags on all leaf switches, with spines being third party
    (non PN) switches.
options:
    pn_spine_list:
      description:
        - Specify list of 3rd party Spine hosts.
      required: False
      type: list
    pn_leaf_list:
      description:
        - Specify list of leaf hosts.
      required: False
      type: list
    pn_update_fabric_to_inband:
      description:
        - Flag to indicate if fabric network should be updated to in-band.
      required: False
      default: False
      type: bool
    pn_stp:
      description:
        - Flag to enable STP at the end.
      required: False
      default: False
      type: bool
"""

EXAMPLES = """
- name: Zero Touch Provisioning - Layer2 setup with 3rd party switches
  pn_l2_third_party:
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


def configure_trunk(module, cluster_node, switch_list, CHANGED_FLAG, task, msg):
    """
    Method to configure trunk vlags.
    :param module: The Ansible module to fetch input parameters.
    :param cluster_node: The node from which lag needs to be created.
    :param switch_list: The list of connected switches to find
    physical linked port.
    :return: Name of the trunk that got created.
    """
    switch_names = ''
    src_ports = []
    for switch in switch_list:
        src_ports += get_ports(module, cluster_node, switch, task, msg)
        switch_names += str(switch)

    src_ports = list(set(src_ports))
    if 'Success' in src_ports:
        module.fail_json(
            unreachable=False,
            msg='L2 configuration failed',
            summary='Unable to find ports to form trunk',
            exception='',
            failed=True,
            changed=True if True in CHANGED_FLAG else False,
            task='Configure L2 (Auto vLags) with existing spine switches'
        )
    name = cluster_node + '-to-' + switch_names
    if len(name) > 59:
        name = name[:59]

    s_ports = ','.join(src_ports)
    CHANGED_FLAG, output = create_trunk(module, cluster_node, name, s_ports, CHANGED_FLAG, task, msg)
    return CHANGED_FLAG, output + name


def configure_trunk_vlag_for_clustered_leafs(module, non_clustered_leafs,
                                             spine_list, CHANGED_FLAG, task, msg):
    """
    Method to create clusters, trunks and vlag for the switches having
    physical links (clustered leafs).
    :param module: The Ansible module to fetch input parameters.
    :param non_clustered_leafs: The list of non clustered leaf switches.
    :param spine_list: The list of spine switches.
    :return: Output of create_cluster() and create_vlag() methods.
    """
    cli = pn_cli(module)
    clicopy = cli
    output = ''
    non_clustered_leafs_count = 0
    while non_clustered_leafs_count == 0:
        if len(non_clustered_leafs) == 0:
            non_clustered_leafs_count += 1
        else:
            node1 = non_clustered_leafs[0]
            non_clustered_leafs.remove(node1)

            cli = clicopy
            cli += ' switch %s lldp-show ' % node1
            cli += ' format sys-name no-show-headers '
            system_names = run_command(module, cli, task, msg).split()
            system_names = list(set(system_names))

            cli = clicopy
            cli += ' switch %s fabric-node-show ' % node1
            cli += ' format name no-show-headers '
            nodes_in_fabric = run_command(module, cli, task, msg).split()
            nodes_in_fabric = list(set(nodes_in_fabric))

            for system in system_names:
                if system not in nodes_in_fabric:
                    system_names.remove(system)

            terminate_flag = 0
            node_count = 0
            while (node_count < len(system_names)) and (terminate_flag == 0):
                node2 = system_names[node_count]
                if node2 in non_clustered_leafs:
                    # Cluster creation
                    cluster_name = node1 + '-to-' + node2 + '-cluster'
                    if len(cluster_name) > 59:
                        cluster_name = cluster_name[:59]

                    mod = 'l2-vrrp'
                    output, CHANGED_FLAG = create_cluster(module, node2, cluster_name,
                                                          node1, node2, mod,
                                                          CHANGED_FLAG, task, msg)

                    non_clustered_leafs.remove(node2)

                    # Trunk creation (leaf to spines)
                    CHANGED_FLAG, trunk_message1 = configure_trunk(module, node1, spine_list,
                                                                   CHANGED_FLAG, task, msg)
                    trunk_message1 = trunk_message1.split('\n')
                    CHANGED_FLAG, trunk_message2 = configure_trunk(module, node2, spine_list,
                                                                   CHANGED_FLAG, task, msg)
                    trunk_message2 = trunk_message2.split('\n')
                    trunk_name1 = trunk_message1[1]
                    trunk_name2 = trunk_message2[1]
                    output += trunk_message1[0] + '\n'
                    output += trunk_message2[0] + '\n'
                    # Vlag creation (leaf to spines)
                    vlag_name = node1 + '-' + node2 + '-to-' + 'spine'
                    if len(vlag_name) > 59:
                        vlag_name = vlag_name[:59]

                    CHANGED_FLAG, output1 = create_vlag(module, vlag_name, node1, trunk_name1,
                                                        node2, trunk_name2, CHANGED_FLAG,
                                                        task, msg)
                    output += output1

                    terminate_flag += 1

                node_count += 1
    return CHANGED_FLAG, output


def configure_trunk_non_clustered_leafs(module, non_clustered_leafs,
                                        spine_list, CHANGED_FLAG, task, msg):
    """
    Method to create clusters, trunks and vlag for non clustered leafs.
    :param module: The Ansible module to fetch input parameters.
    :param non_clustered_leafs: The list of all non clustered leaf switches.
    :param spine_list: The list of all spine switches.
    :return: Output of configure_trunk() method.
    """
    output = ''
    for leaf in non_clustered_leafs:
        # Trunk creation (leaf to spines)
        trunk_message = configure_trunk(module, leaf, spine_list, CHANGED_FLAG, task, msg)
        trunk_message = trunk_message.split('\n')
        output += trunk_message[0] + '\n'

    return CHANGED_FLAG, output


def configure_auto_vlag(module, CHANGED_FLAG, task, msg):
    """
    Method to create and configure vlag.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing output of configuration.
    """
    output = ''
    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']

    # Configure trunk, vlag for clustered leaf switches.
    CHANGED_FLAG, output1 = configure_trunk_vlag_for_clustered_leafs(module, list(leaf_list),
                                                                     spine_list, CHANGED_FLAG,
                                                                     task, msg)
    output += output1

    # Configure trunk, vlag for non clustered leaf switches.
    non_clustered_leafs = find_non_clustered_leafs(module, task, msg)
    CHANGED_FLAG, output1 = configure_trunk_non_clustered_leafs(module, non_clustered_leafs,
                                                                spine_list, CHANGED_FLAG,
                                                                task, msg)
    output += output1

    return CHANGED_FLAG, output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_update_fabric_to_inband=dict(required=False, type='bool',
                                            default=False),
            pn_stp=dict(required=False, type='bool', default=False),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Configure L2 (Auto vLags) with existing spine switches'
    msg = 'L2 configuration failed'

    switch_list = module.params['pn_leaf_list']

    # L2 setup (auto vLags).
    CHANGED_FLAG, message = configure_auto_vlag(module, CHANGED_FLAG, task, msg)

    # Update fabric network to in-band if flag is True.
    if module.params['pn_update_fabric_to_inband']:
        for switch in switch_list:
            message += update_fabric_network_to_inband(module, switch, task, msg)

    # Enable STP if flag is True.
    if module.params['pn_stp']:
        for switch in switch_list:
            CHANGED_FLAG, output = modify_stp(module, 'enable', switch, CHANGED_FLAG, task, msg)
            message += output

    results = []
    for switch in switch_list:
        replace_string = switch + ': '
        for line in message.splitlines():
            if replace_string in line:
                json_msg = {
                    'switch': switch,
                    'output': (line.replace(replace_string, '')).strip()
                }
                results.append(json_msg)

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        msg='L2 configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure L2 (Auto vLags) with existing spine switches'
    )


if __name__ == '__main__':
    main()
