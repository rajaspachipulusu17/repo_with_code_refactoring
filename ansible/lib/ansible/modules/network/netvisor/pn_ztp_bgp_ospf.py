#!/usr/bin/python
""" PN CLI BGP/OSPF """

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import *

DOCUMENTATION = """
---
module: pn_ztp_bgp_ospf
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to configure eBGP/OSPF.
description: It performs following steps:
    EBGP:
      - Assigning bgp_as
      - Configuring bgp_redistribute
      - Configuring bgp_maxpath
      - Assign ebgp_neighbor
      - Assign router_id
      - Create leaf_cluster
      - Add iBGP neighbor for clustered leaf
    OSPF:
      - Find area_id for leafs
      - Assign ospf_neighbor for leaf cluster
      - Assign ospf_neighbor
      - Assign ospf_redistribute
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
    pn_bgp_redistribute:
      description:
        - Specify bgp_redistribute value to be added to vrouter.
      required: False
      type: str
      choices: ['none', 'static', 'connected', 'rip', 'ospf']
      default: 'connected'
    pn_bgp_maxpath:
      description:
        - Specify bgp_maxpath value to be added to vrouter.
      required: False
      type: str
      default: '16'
    pn_bgp_as_range:
      description:
        - Specify bgp_as_range value to be added to vrouter.
      required: False
      type: str
      default: '65000'
    pn_routing_protocol:
      description:
        - Specify which routing protocol to specify.
      required: False
      type: str
      choices: ['ebgp', 'ospf']
    pn_ibgp_ip_range:
      description:
        - Specify ip range for ibgp interface.
      required: False
      type: str
      default: '75.75.75.0/30'
    pn_ibgp_vlan:
      description:
        - Specify vlan for ibgp interface.
      required: False
      type: str
      default: '4040'
    pn_bfd:
      description:
        - Specify bfd flag for the ebgp neighbor.
      required: False
      type: bool
      default: False
    pn_ospf_v4_area_id:
      description:
        - Specify area_id value to be added to vrouter for ospf v4.
      required: False
      type: str
      default: '0'
    pn_ospf_v6_area_id:
      description:
        - Specify area_id value to be added to vrouter for ospf v6.
      required: False
      type: str
      default: '0.0.0.0'
    pn_area_configure_flag:
      description:
        - Specify the type of area
      required: False
      choices=['singlearea', 'dualarea', 'multiarea']
      default: 'singlearea'
    pn_jumbo_frames:
      description:
        - Flag to assign mtu
      required: False
      default: False
      type: bool
"""

EXAMPLES = """
- name: Configure eBGP/OSPF
  pn_ztp_bgp_ospf:
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
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)
    results = []
    if out:
        return out

    if err:
        json_msg = {
            'switch': '',
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception='',
            summary=results,
            task='Configure eBGP/OSPF',
            stderr=err.strip(),
            msg='eBGP/OSPF configuration failed',
            changed=False
        )
    else:
        return 'Success'


def find_bgp_as_dict(module):
    """
    Method to find bgp-as for all switches and store it in a dictionary.
    :param module: The Ansible module to fetch input parameters.
    :return: Dictionary containing switch: bgp_as key value pairs.
    """
    leaf_list = module.params['pn_leaf_list']
    bgp_as = int(module.params['pn_bgp_as_range'])
    cluster_leaf_list = []
    cli = pn_cli(module)
    clicopy = cli
    dict_bgp_as = {}

    for spine in module.params['pn_spine_list']:
        dict_bgp_as[spine] = str(bgp_as)

    cli += ' cluster-show format name no-show-headers'
    cluster_list = run_cli(module, cli).split()

    if 'Success' not in cluster_list:
        for cluster in cluster_list:
            cli = clicopy
            cli += ' cluster-show name %s' % cluster
            cli += ' format cluster-node-1,cluster-node-2 no-show-headers'
            cluster_nodes = run_cli(module, cli).split()

            if cluster_nodes[0] in leaf_list and cluster_nodes[1] in leaf_list:
                bgp_as += 1
                dict_bgp_as[cluster_nodes[0]] = str(bgp_as)
                dict_bgp_as[cluster_nodes[1]] = str(bgp_as)
                cluster_leaf_list.append(cluster_nodes[0])
                cluster_leaf_list.append(cluster_nodes[1])

    non_clustered_leaf_list = list(set(leaf_list) - set(cluster_leaf_list))
    for leaf in non_clustered_leaf_list:
        bgp_as += 1
        dict_bgp_as[leaf] = str(bgp_as)

    return dict_bgp_as


def vrouter_interface_ibgp_add(module, switch_name, interface_ip, neighbor_ip,
                               remote_as):
    """
    Method to create interfaces and add ibgp neighbors.
    :param module: The Ansible module to fetch input parameters.
    :param switch_name: The name of the switch to run interface.
    :param interface_ip: Interface ip to create a vrouter interface.
    :param neighbor_ip: Neighbor_ip for the ibgp neighbor.
    :param remote_as: Bgp-as for remote switch.
    :return: String describing if ibgp neighbours got added or already exists.
    """
    global CHANGED_FLAG
    output = ''
    vlan_id = module.params['pn_ibgp_vlan']

    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch %s vlan-show format id no-show-headers ' % switch_name
    existing_vlans = run_cli(module, cli).split()

    if vlan_id not in existing_vlans:
        cli = clicopy
        cli += ' switch %s vlan-create id %s scope local ' % (switch_name,
                                                              vlan_id)
        run_cli(module, cli)

        output += ' %s: Created vlan with id %s \n' % (switch_name, vlan_id)
        CHANGED_FLAG.append(True)

    cli = clicopy
    cli += ' vrouter-show location %s format name' % switch_name
    cli += ' no-show-headers'
    vrouter = run_cli(module, cli).split()[0]

    cli = clicopy
    cli += ' vrouter-interface-show ip %s vlan %s' % (interface_ip, vlan_id)
    cli += ' format switch no-show-headers'
    existing_vrouter_interface = run_cli(module, cli).split()

    if vrouter not in existing_vrouter_interface:
        cli = clicopy
        cli += ' vrouter-interface-add vrouter-name %s ip %s vlan %s ' % (
            vrouter, interface_ip, vlan_id
        )
        run_cli(module, cli)

        output += ' %s: Added vrouter interface with ip %s on %s \n' % (
            switch_name, interface_ip, vrouter
        )
        CHANGED_FLAG.append(True)

    neighbor_ip = neighbor_ip.split('/')[0]
    cli = clicopy
    cli += ' vrouter-bgp-show remote-as ' + remote_as
    cli += ' neighbor %s format switch no-show-headers' % neighbor_ip
    already_added = run_cli(module, cli).split()

    if vrouter not in already_added:
        cli = clicopy
        cli += ' vrouter-bgp-add vrouter-name %s' % vrouter
        cli += ' neighbor %s remote-as %s next-hop-self' % (neighbor_ip,
                                                            remote_as)
        if module.params['pn_bfd']:
            cli += ' bfd '

        if 'Success' in run_cli(module, cli):
            output += ' %s: Added iBGP neighbor %s for %s \n' % (switch_name,
                                                                 neighbor_ip,
                                                                 vrouter)
            CHANGED_FLAG.append(True)

    return output


def assign_ibgp_interface(module, dict_bgp_as):
    """
    Method to create interfaces and add ibgp neighbors.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: The dictionary containing bgp-as of all switches.
    :return: The output of vrouter_interface_ibgp_add() method.
    """
    output = ''
    ibgp_ip_range = module.params['pn_ibgp_ip_range']
    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    subnet_count = 0
    supernet = 30

    cli = pn_cli(module)
    clicopy = cli

    address = ibgp_ip_range.split('.')
    static_part = str(address[0]) + '.' + str(address[1]) + '.'
    static_part += str(address[2]) + '.'

    cli += ' cluster-show format name no-show-headers '
    cluster_list = run_cli(module, cli).split()

    if len(cluster_list) > 0 and cluster_list[0] != 'Success':
        for cluster in cluster_list:
            cli = clicopy
            cli += ' cluster-show name %s format cluster-node-1' % cluster
            cli += ' no-show-headers'
            cluster_node_1 = run_cli(module, cli).split()[0]

            if cluster_node_1 not in spine_list and cluster_node_1 in leaf_list:
                ip_count = subnet_count * 4
                ip1 = static_part + str(ip_count + 1) + '/' + str(supernet)
                ip2 = static_part + str(ip_count + 2) + '/' + str(supernet)

                cli = clicopy
                cli += ' cluster-show name %s format cluster-node-2' % cluster
                cli += ' no-show-headers'
                cluster_node_2 = run_cli(module, cli).split()[0]

                remote_as = dict_bgp_as[cluster_node_1]
                output += vrouter_interface_ibgp_add(module, cluster_node_1,
                                                     ip1, ip2, remote_as)
                output += vrouter_interface_ibgp_add(module, cluster_node_2,
                                                     ip2, ip1, remote_as)

                subnet_count += 1
    else:
        output += ' No leaf clusters present to add iBGP \n'

    return output


def add_bgp_neighbor(module, dict_bgp_as):
    """
    Method to add bgp_neighbor to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: Dictionary containing bgp-as of all switches.
    :return: String describing if bgp neighbors got added or not.
    """
    global CHANGED_FLAG
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    for spine in module.params['pn_spine_list']:
        cli = clicopy
        cli += ' vrouter-show location %s' % spine
        cli += ' format name no-show-headers'
        vrouter_spine = run_cli(module, cli).split()[0]

        cli = clicopy
        cli += ' vrouter-interface-show vrouter-name %s ' % vrouter_spine
        cli += ' format l3-port no-show-headers '
        port_list = run_cli(module, cli).split()
        port_list = list(set(port_list))
        port_list.remove(vrouter_spine)

        for port in port_list:
            cli = clicopy
            cli += ' switch %s port-show port %s ' % (spine, port)
            cli += ' format hostname no-show-headers '
            leaf = run_cli(module, cli).split()[0]

            cli = clicopy
            cli += ' vrouter-show location %s' % leaf
            cli += ' format name no-show-headers'
            vrouter_leaf = run_cli(module, cli).split()[0]

            bgp_leaf = dict_bgp_as[leaf]
            bgp_spine = dict_bgp_as[spine]

            cli = clicopy
            cli += ' vrouter-interface-show vrouter-name %s ' % vrouter_spine
            cli += ' l3-port %s format ip no-show-headers ' % port
            ip = run_cli(module, cli).split()
            ip = list(set(ip))
            ip.remove(vrouter_spine)
            ip = ip[0]

            ip = ip.split('/')[0]
            ip_spine = ip

            ip = ip.split('.')
            static_part = str(ip[0]) + '.' + str(ip[1]) + '.'
            static_part += str(ip[2]) + '.'
            leaf_last_octet = int(ip[3]) - 1
            ip_leaf = static_part + str(leaf_last_octet)

            cli = clicopy
            cli += ' vrouter-bgp-show remote-as ' + bgp_leaf
            cli += ' neighbor %s format switch no-show-headers ' % ip_leaf
            already_added = run_cli(module, cli).split()

            if vrouter_spine in already_added:
                output += ''
            else:
                cli = clicopy
                cli += ' vrouter-bgp-add vrouter-name ' + vrouter_spine
                cli += ' neighbor %s remote-as %s ' % (ip_leaf,
                                                       bgp_leaf)
                if module.params['pn_bfd']:
                    cli += ' bfd '

                if 'Success' in run_cli(module, cli):
                    output += ' %s: Added BGP Neighbor %s for %s \n' % (
                        spine, ip_leaf, vrouter_spine
                    )
                    CHANGED_FLAG.append(True)

            cli = clicopy
            cli += ' vrouter-bgp-show remote-as ' + bgp_spine
            cli += ' neighbor %s format switch no-show-headers ' % (
                ip_spine)
            already_added = run_cli(module, cli).split()

            if vrouter_leaf in already_added:
                output += ''
            else:
                cli = clicopy
                cli += ' vrouter-bgp-add vrouter-name ' + vrouter_leaf
                cli += ' neighbor %s remote-as %s ' % (ip_spine,
                                                       bgp_spine)
                if module.params['pn_bfd']:
                    cli += ' bfd '

                temp_cli = clicopy
                temp_cli += ' cluster-show format name no-show-headers'
                cluster_list = run_cli(module, temp_cli).split()
                for cluster in cluster_list:
                    if leaf in cluster:
                        cli += ' weight 100 allowas-in '
                        break

                if 'Success' in run_cli(module, cli):
                    output += ' %s: Added BGP Neighbor %s for %s \n' % (
                        leaf, ip_spine, vrouter_leaf
                    )
                    CHANGED_FLAG.append(True)

    return output


def configure_bgp(module, vrouter_names, dict_bgp_as, bgp_max, bgp_redis):
    """
    Method to add bgp_as, bgp_max_path and bgp_redistribute to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: Dictionary containing the bgp-as for all the switches.
    :param vrouter_names: List of vrouter names.
    :param bgp_max: Maxpath for bgp.
    :param bgp_redis: Bgp redistribute for bgp.
    :return: String describing if bgp config got added or not.
    """
    global CHANGED_FLAG
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    for vrouter in vrouter_names:
        cli = clicopy
        cli += ' vrouter-show name ' + vrouter
        cli += ' format location no-show-headers '
        switch = run_cli(module, cli).split()[0]

        cli = clicopy
        cli += ' vrouter-modify name %s ' % vrouter
        cli += ' bgp-as %s ' % dict_bgp_as[switch]
        cli += ' bgp-max-paths %s ' % bgp_max
        cli += ' bgp-redistribute %s ' % bgp_redis
        if 'Success' in run_cli(module, cli):
            output += ' %s: Added bgp_redistribute %s ' % (switch, bgp_redis)
            output += 'bgp_as %s bgp_maxpath %s to %s\n' % (dict_bgp_as[switch],
                                                            bgp_max, vrouter)
            CHANGED_FLAG.append(True)

    return output


def find_non_clustered_leafs(module):
    """
    Method to find leafs which are not part of any cluster.
    :param module: The Ansible module to fetch input parameters.
    :return: List of non clustered leaf switches.
    """
    non_clustered_leafs = []
    cli = pn_cli(module)
    cli += ' cluster-show format cluster-node-1,cluster-node-2 '
    cli += ' no-show-headers '
    clustered_nodes = run_cli(module, cli).split()

    for leaf in module.params['pn_leaf_list']:
        if leaf not in clustered_nodes:
            non_clustered_leafs.append(leaf)

    return non_clustered_leafs


def create_cluster(module, name, node1, node2):
    """
    Method to create a cluster between two switches.
    :param module: The Ansible module to fetch input parameters.
    :param name: The name of the cluster to create.
    :param node1: First node of the cluster.
    :param node2: Second node of the cluster.
    :return: String describing if cluster got created or not.
    """
    global CHANGED_FLAG
    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch %s cluster-show format name no-show-headers ' % node1
    cluster_list = run_cli(module, cli).split()
    if name not in cluster_list:
        cli = clicopy
        cli += ' switch %s cluster-create name %s ' % (node1, name)
        cli += ' cluster-node-1 %s cluster-node-2 %s ' % (node1, node2)
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)
            return ' %s: Created %s \n' % (node1, name)
    else:
        return ''


def create_leaf_clusters(module):
    """
    Method to create cluster between two physically connected leaf switches.
    :param module: The Ansible module to fetch input parameters.
    :return: Output of create_cluster() method.
    """
    output = ''
    non_clustered_leafs = find_non_clustered_leafs(module)
    non_clustered_leafs_count = 0
    cli = pn_cli(module)
    clicopy = cli

    while non_clustered_leafs_count == 0:
        if len(non_clustered_leafs) == 0:
            non_clustered_leafs_count += 1
        else:
            node1 = non_clustered_leafs[0]
            non_clustered_leafs.remove(node1)

            cli = clicopy
            cli += ' switch %s lldp-show ' % node1
            cli += ' format sys-name no-show-headers '
            system_names = run_cli(module, cli).split()
            system_names = list(set(system_names))

            cli = clicopy
            cli += ' switch %s fabric-node-show ' % node1
            cli += ' format name no-show-headers '
            nodes_in_fabric = run_cli(module, cli).split()
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
                    output += create_cluster(module, cluster_name, node1, node2)

                    non_clustered_leafs.remove(node2)
                    terminate_flag += 1

                node_count += 1

    return output


def configure_ospf_bfd(module, vrouter, ip):
    """
    Method to add ospf_bfd to the vrouter.
    :param module: The Ansible module to fetch input parameters.
    :param vrouter: The vrouter name to add ospf bfd.
    :param ip: The interface ip to associate the ospf bfd.
    :return: String describing if OSPF BFD got added or if it already exists.
    """
    global CHANGED_FLAG
    cli = pn_cli(module)
    clicopy = cli
    cli += ' vrouter-interface-show vrouter-name %s' % vrouter
    cli += ' ip %s format nic no-show-headers ' % ip
    nic_interface = run_cli(module, cli).split()
    nic_interface = list(set(nic_interface))
    nic_interface.remove(vrouter)

    cli = clicopy
    cli += ' vrouter-interface-config-show vrouter-name %s' % vrouter
    cli += ' nic %s format ospf-bfd no-show-headers ' % nic_interface[0]
    ospf_status = run_cli(module, cli).split()
    ospf_status = list(set(ospf_status))

    cli = clicopy
    cli += ' vrouter-show name ' + vrouter
    cli += ' format location no-show-headers '
    switch = run_cli(module, cli).split()[0]

    if 'Success' in ospf_status:
        cli = clicopy
        cli += ' vrouter-interface-config-add vrouter-name %s' % vrouter
        cli += ' nic %s ospf-bfd enable' % nic_interface[0]
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)
            return ' %s: Added OSPF BFD config to %s \n' % (switch, vrouter)
    elif 'enable' not in ospf_status:
        ospf_status.remove(vrouter)
        cli = clicopy
        cli += ' vrouter-interface-config-modify vrouter-name %s' % vrouter
        cli += ' nic %s ospf-bfd enable' % nic_interface[0]
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)
            return ' %s: Enabled OSPF BFD for %s \n' % (switch, vrouter)
    else:
        return ''


def add_ospf_loopback(module, current_switch):
    """
    Method to add loopback network to OSPF
    :param module: The Ansible module to fetch input parameters.
    :param current_switch: Switch to add network statements.
    :return: String describing if loopback network got added to OSPF or not.
    """
    global CHANGED_FLAG
    output = ''
    cli = pn_cli(module)
    cli += ' switch %s ' % current_switch
    clicopy = cli
    vr_name = current_switch + '-vrouter'

    cli += ' vrouter-loopback-interface-show vrouter-name %s' % vr_name
    cli += ' format ip,router-if parsable-delim ,'
    loopback_ip = run_cli(module, cli).strip().split('\n')
    for addr in loopback_ip:
        ip1 = addr.split(',')
        ip = ip1[1]
        if len(ip.split('.')) == 1:
            nic = ip1[2]
            cli = clicopy
            cli += ' vrouter-ospf6-show vrouter-name %s' % vr_name
            cli += ' nic %s no-show-headers ' % nic
            already_added = run_cli(module, cli)
            if 'Success' in already_added:
                cli = clicopy
                cli += ' vrouter-ospf6-add vrouter-name %s' % vr_name
                cli += ' nic %s' % nic
                cli += ' ospf6-area %s' % module.params['pn_ospf_v6_area_id']
                output += run_cli(module, cli)

            # Add loopback interface 'lo' to ospf6
            cli = clicopy
            nic = "lo"
            cli += ' vrouter-ospf6-show vrouter-name %s' % vr_name
            cli += ' nic %s no-show-headers ' % nic
            already_added = run_cli(module, cli)
            if 'Success' in already_added:
                cli = clicopy
                cli += ' vrouter-ospf6-add vrouter-name %s' % vr_name
                cli += ' nic %s' % nic
                cli += ' ospf6-area %s' % module.params['pn_ospf_v6_area_id']
                output += run_cli(module, cli)
        else:
            l_ip = ip1[1]
            cli = clicopy
            cli += ' vrouter-ospf-show vrouter-name %s' % vr_name
            cli += ' network %s no-show-headers ' % l_ip
            already_added = run_cli(module, cli).split()
            if 'Success' in already_added:
                cli = clicopy
                cli += ' vrouter-ospf-add vrouter-name %s' % vr_name
                cli += ' network %s/32' % l_ip
                cli += ' ospf-area %s' % module.params['pn_ospf_v4_area_id']
                output += run_cli(module, cli)

    return output


def add_ospf_neighbor(module, current_switch):
    """
    Method to add ospf_neighbor to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_area_id: Dictionary containing area_id of leafs.
    :return: String describing if ospf neighbors got added or not.
    """
    global CHANGED_FLAG
    output = ''
    addr_type = module.params['pn_addr_type']
    cli = pn_cli(module)
    cli += ' switch %s ' % current_switch
    clicopy = cli

    vrouter = current_switch + '-vrouter'

    cli = clicopy
    cli += ' vrouter-interface-show vrouter-name %s ' % vrouter
    cli += ' format l3-port no-show-headers '
    port_list = run_cli(module, cli).split()
    port_list = list(set(port_list))
    port_list.remove(vrouter)

    if module.params['pn_area_configure_flag'] == 'singlearea':
        ospf_area_id = module.params['pn_ospf_v4_area_id']
    else:
        ospf_area_id = str(int(module.params['pn_ospf_v4_area_id']) + 1)

    for port in port_list:
        cli = clicopy
        cli += ' vrouter-interface-show vrouter-name %s l3-port %s' % (
            vrouter, port
        )
        cli += ' format ip no-show-headers'
        ip = run_cli(module, cli).split()
        ip = list(set(ip))
        ip.remove(vrouter)
        ip = ip[0]
        ip_switch = ip

        if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
            ip = ip.split('.')
            static_part = str(ip[0]) + '.' + str(ip[1]) + '.'
            static_part += str(ip[2]) + '.'
            last_octet = str(ip[3]).split('/')
            netmask = last_octet[1]

            last_octet_ip_mod = int(last_octet[0]) % (1 << (32 - int(netmask)))
            ospf_last_octet = int(last_octet[0]) - last_octet_ip_mod
            ospf_network = static_part + str(ospf_last_octet) + '/' + netmask
#            elif addr_type == 'ipv6':
#                ip = ip.split('/')
#                ip_spine = ip[0]
#                netmask = ip[1]
#                ip = ip[0]
#
#                ip = ip.split(':')
#                if not ip[-1]:
#                    ip[-1] = '0'
#                #leaf_last_octet = hex(int(ip[-1], 16) + 1)[2:]
#                last_octet_ipv6 = int(ip[-1], 16)
#                last_octet_ipv6_mod = last_octet_ipv6 % (1 << (128 - int(netmask)))
#                ospf_last_octet = hex(last_octet_ipv6 - last_octet_ipv6_mod)[2:]
#                leaf_last_octet = hex(last_octet_ipv6 + 1)[2:]
#                ip[-1] = str(leaf_last_octet)
#                ip_leaf = ':'.join(ip)
#                ip[-1] = str(ospf_last_octet)
#                ospf_network = ':'.join(ip) + '/' + netmask

        if addr_type == 'ipv4_ipv6':
            cli = clicopy
            cli += ' vrouter-interface-show vrouter-name %s l3-port %s' % (
                vrouter, port)
            cli += ' format ip2 no-show-headers'
            ip2 = run_cli(module, cli).split()
            ip2 = list(set(ip2))
            ip2.remove(vrouter)
            ip_switch_ipv6 = ip2[0]

            cli = clicopy
            cli += 'vrouter-interface-show vrouter-name %s' % vrouter
            cli += ' ip2 %s format nic no-show-headers ' % ip_switch_ipv6
            nic = run_cli(module, cli).split()
            nic = list(set(nic))
            nic.remove(vrouter)
            nic = nic[0]

            cli = clicopy
            cli += 'vrouter-ospf6-show nic %s format switch no-show-headers ' % nic
            ipv6_vrouter = run_cli(module, cli).split()

            if vrouter not in ipv6_vrouter:
                cli = clicopy
                cli += 'vrouter-ospf6-add vrouter-name %s nic %s ospf6-area %s ' % (
                    vrouter, nic, module.params['pn_ospf_v6_area_id'])
                run_cli(module, cli)
                output += ' %s: Added OSPF6 nic %s to %s \n' % (
                    current_switch, nic, vrouter
                )

        cli = clicopy
        cli += ' vrouter-ospf-show'
        cli += ' network %s format switch no-show-headers ' % ospf_network
        already_added = run_cli(module, cli).split()

        if vrouter in already_added:
            pass
        else:
            if module.params['pn_bfd']:
                output += configure_ospf_bfd(module, vrouter,
                                             ip_switch)

            cli = clicopy
            cli += ' vrouter-ospf-add vrouter-name ' + vrouter
            cli += ' network %s ospf-area %s' % (ospf_network,
                                                 ospf_area_id)

            if 'Success' in run_cli(module, cli):
                output += ' %s: Added OSPF neighbor %s to %s \n' % (
                    current_switch, ospf_network, vrouter
                )
                CHANGED_FLAG.append(True)

    return output


def add_ospf_redistribute(module, current_switch):
    """
    Method to add ospf_redistribute to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param vrouter_names: List of vrouter names.
    :return: String describing if ospf-redistribute got added or not.
    """
    global CHANGED_FLAG
    output = ''
    pn_ospf_redistribute = module.params['pn_ospf_redistribute']
    cli = pn_cli(module)
    clicopy = cli
    vrouter = current_switch + '-vrouter'

    cli = clicopy
    cli += ' vrouter-modify name %s' % vrouter
    cli += ' ospf-redistribute %s' % pn_ospf_redistribute
    if 'Success' in run_cli(module, cli):
        output += ' %s: Added ospf_redistribute to %s \n' % (current_switch,
                                                             vrouter)
        CHANGED_FLAG.append(True)

    return output

def vrouter_iospf_interface_add(module, switch_name, ip_addr, ip2_addr, ospf_area_id, p2p):
    """
    Method to create interfaces and add ospf neighbors.
    :param module: The Ansible module to fetch input parameters.
    :param switch_name: The name of the switch to run interface.
    :param ip_addr: Interface ipv4 address to create a vrouter interface.
    :param ip2_addr: Interface ipv6 address to create a vrouter interface.
    :param ospf_area_id: The area_id for ospf neighborship.
    :return: String describing if ospf neighbors got added or not.
    """
    global CHANGED_FLAG
    output = ''
    vlan_id = module.params['pn_iospf_vlan']
    pim_ssm = module.params['pn_pim_ssm']
    ospf_cost = module.params['pn_ospf_cost']

    cli = pn_cli(module)
    clicopy = cli
    cli += ' vrouter-show location %s format name' % switch_name
    cli += ' no-show-headers'
    vrouter = run_cli(module, cli).split()[0]

    cli = clicopy
    cli += ' vrouter-interface-show ip %s vlan %s' % (ip_addr, vlan_id)
    cli += ' format switch no-show-headers'
    existing_vrouter_interface = run_cli(module, cli).split()

    if vrouter not in existing_vrouter_interface:
        cli = clicopy
        cli += ' vrouter-interface-add vrouter-name %s vlan %s ip %s' % (
            vrouter, vlan_id, ip_addr
        )
        if ip2_addr:
            cli += ' ip2 %s' % (ip2_addr)
        if pim_ssm == True:
            cli += ' pim-cluster '
        if module.params['pn_jumbo_frames'] == True:
            cli += ' mtu 9216'
        run_cli(module, cli)
        ip_msg = 'ip %s' % (ip_addr)
        if ip2_addr:
            ip_msg += ' ip2 %s' % (ip2_addr)
        output += ' %s: Added vrouter interface with %s on %s \n' % (
            switch_name, ip_msg, vrouter
        )
        CHANGED_FLAG.append(True)

    cli = clicopy
    cli += ' vrouter-interface-show vlan %s ' % vlan_id
    cli += ' vrouter-name %s format nic parsable-delim ,' % vrouter
    nic = run_cli(module, cli).split(',')[1]

    cli = clicopy
    cli += ' vrouter-interface-config-show vrouter-name %s' % vrouter
    cli += ' nic %s no-show-headers ' % nic
    config_exists = run_cli(module, cli).split()
    cli = clicopy
    if 'Success' in config_exists:
        cli += ' vrouter-interface-config-add vrouter-name %s' % vrouter
        cli += ' nic %s ospf-cost %s' % (nic, ospf_cost)
    else:
        cli += ' vrouter-interface-config-modify vrouter-name %s' % vrouter
        cli += ' nic %s ospf-cost %s' % (nic, ospf_cost)
    if p2p:
        cli += ' ospf-network-type point-to-point'
    run_cli(module, cli)

    cli = clicopy
    cli += ' vrouter-ospf-show'
    cli += ' network %s format switch no-show-headers ' % ip_addr
    already_added = run_cli(module, cli).split()

    if vrouter in already_added:
        pass
    else:
        ip_addr_without_subnet = ip_addr.split('/')[0]
        if module.params['pn_bfd']:
            output += configure_ospf_bfd(module, vrouter,
                                         ip_addr_without_subnet)
        cli = clicopy
        cli += ' vrouter-ospf-add vrouter-name ' + vrouter
        cli += ' network %s ospf-area %s' % (ip_addr, ospf_area_id)

        if 'Success' in run_cli(module, cli):
            output += ' %s: Added OSPF neighbor %s to %s \n' % (
                switch_name, ip_addr, vrouter
            )
            CHANGED_FLAG.append(True)

    if ip2_addr:
            cli = clicopy
            cli += 'vrouter-ospf6-show nic %s format switch no-show-headers ' % nic
            ip2_vrouter = run_cli(module, cli).split()

            if vrouter not in ip2_vrouter:
                cli = clicopy
                cli += 'vrouter-ospf6-add vrouter-name %s nic %s ospf6-area %s ' % (
                    vrouter, nic, module.params['pn_ospf_v6_area_id'])
                run_cli(module, cli)
                output += ' %s: Added OSPF6 nic %s to %s \n' % (
                    switch_name, nic, vrouter
                )

    return output

def vrouter_iospf_vlan_ports_add(module, switch_name, cluster_ports):
    """
    Method to create iOSPF vlan and add ports to it
    :param module: The Ansible module to fetch input parameters.
    :param switch_name: The name of the switch to run interface.
    :return: String describing if ospf vlan got added or not.
    """
    global CHANGED_FLAG
    output = ''
    vlan_id = module.params['pn_iospf_vlan']

    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch %s vlan-show format id no-show-headers ' % switch_name
    existing_vlans = run_cli(module, cli).split()

    if vlan_id not in existing_vlans:
        cli = clicopy
        cli += ' switch %s vlan-create id %s scope cluster ' % (switch_name,
                                                                vlan_id)
        cli += ' ports none description iOSPF-cluster-vlan '
        run_cli(module, cli)
        output = ' %s: Created vlan with id %s \n' % (switch_name, vlan_id)

    cli = clicopy
    cli += ' switch %s vlan-port-add vlan-id %s ports %s' % (switch_name, vlan_id, cluster_ports)
    run_cli(module, cli)
    CHANGED_FLAG.append(True)

    return output


def assign_leafcluster_ospf_interface(module):
    """
    Method to create interfaces and add ospf neighbor for leaf cluster.
    :param module: The Ansible module to fetch input parameters.
    :param dict_area_id: Dictionary containing area_id of leafs.
    :return: The output of vrouter_interface_ibgp_add() method.
    """
    output = ''
    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    iospf_v4_range = module.params['pn_iospf_ipv4_range']
    cidr_v4 = int(module.params['pn_cidr_ipv4'])
    subnet_v4 = module.params['pn_subnet_ipv4']
    iospf_v6_range = module.params['pn_iospf_ipv6_range']
    cidr_v6 = int(module.params['pn_cidr_ipv6'])
    subnet_v6 = module.params['pn_subnet_ipv6']
    addr_type = module.params['pn_addr_type']

    cli = pn_cli(module)
    clicopy = cli

    if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
        available_ips_ipv4 = calculate_link_ip_addresses_ipv4(iospf_v4_range, cidr_v4, subnet_v4)

    if addr_type == 'ipv6' or addr_type == 'ipv4_ipv6':
        get_count = 2 if subnet_v6 == '127' else 3
        available_ips_ipv6 = calculate_link_ip_addresses_ipv6(iospf_v6_range, cidr_v6, subnet_v6,
                                                              get_count)


    cli += ' cluster-show format name no-show-headers '
    cluster_list = run_cli(module, cli).split()

    if len(cluster_list) > 0 and cluster_list[0] != 'Success':
        if module.params['pn_area_configure_flag'] == 'singlearea':
            ospf_area_id = module.params['pn_ospf_v4_area_id']
        else:
            ospf_area_id = str(int(module.params['pn_ospf_v4_area_id']) + 1)

        point_to_point = False
        if subnet_v4 == '31' or subnet_v6 == '127':
            point_to_point = True
        for cluster in cluster_list:
            cli = clicopy
            cli += ' cluster-show name %s format cluster-node-1,' % cluster
            cli += 'ports,cluster-node-2,remote-ports no-show-headers'
            cluster_node_1, cluster_ports_1, cluster_node_2, cluster_ports_2 = run_cli(module, cli).split()
            ipv4_1, ipv4_2 = available_ips_ipv4[0:2]
            available_ips_ipv4.remove(ipv4_1)
            available_ips_ipv4.remove(ipv4_2)
            if addr_type == 'ipv6' or addr_type == 'ipv4_ipv6':
                ip_list = available_ips_ipv6.next()
                if subnet_v6 == '127':
                    ipv6_1, ipv6_2 = ip_list[0:2]
                else:
                    ipv6_1, ipv6_2 = ip_list[1:3]
            else:
                ipv6_1 = ipv6_2 = None
            if cluster_node_1 not in spine_list and cluster_node_1 in leaf_list:
                output += vrouter_iospf_vlan_ports_add(module, cluster_node_1, cluster_ports_1)
                output += vrouter_iospf_interface_add(module, cluster_node_1, ipv4_1, ipv6_1,
                                                      ospf_area_id, point_to_point)
                output += vrouter_iospf_vlan_ports_add(module, cluster_node_2, cluster_ports_2)
                output += vrouter_iospf_interface_add(module, cluster_node_2, ipv4_2, ipv6_2,
                                                      ospf_area_id, point_to_point)
    else:
        output += ' No leaf clusters present to add iOSPF \n'

    return output


def make_interface_passive(module, current_switch):
    """
    Method to make VRRP interfaces ospf passive.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing if ospf passive interfaces changed or not.
    """
    output = ''
    cli = pn_cli(module)
    clicopy = cli
    addr_type = module.params['pn_addr_type']

    vrname = "%s-vrouter" % current_switch
    cli = clicopy
    cli += ' switch %s vrouter-interface-config-show vrouter-name ' % current_switch
    cli += ' %s format nic,ospf-passive-if parsable-delim ,' % vrname
    pass_intf = run_cli(module, cli).split()
    passv_info = {}
    for intf in pass_intf:
        if not intf:
            break
        vrname, intf_index, passv = intf.split(',')
        passv_info[intf_index] = passv

    cli = clicopy
    cli += ' switch %s vrouter-interface-show vrouter-name %s ' % (current_switch, vrname)
    cli += ' format is-vip,is-primary,nic parsable-delim ,'
    intf_info = run_cli(module, cli).split()
    for intf in intf_info:
        if not intf:
            output += "No router interface exist"
        vrname, is_vip, is_primary, intf_index = intf.split(',')
        if is_vip == 'true' or is_primary == 'true':
            if intf_index in passv_info:
                if passv_info[intf_index] == "false":
                    cli = clicopy
                    cli += ' vrouter-interface-config-modify vrouter-name %s ' % vrname
                    cli += ' nic %s ospf-passive-if ' % intf_index
                    run_cli(module, cli)
            else:
                cli = clicopy
                cli += ' vrouter-interface-config-add vrouter-name %s ' % vrname
                cli += ' nic %s ospf-passive-if ' % intf_index
                run_cli(module, cli)
                output += '%s: Added OSPF nic %s to %s \n' % (
                vrname, intf_index, vrname
            )
            CHANGED_FLAG.append(True)

    # Add interface config to 'lo'
    if addr_type == 'ipv4_ipv6' or addr_type == 'ipv6':
        cli = clicopy
        cli += ' vrouter-interface-config-add vrouter-name %s ' % vrname
        cli += ' nic lo ospf-passive-if '
        run_cli(module, cli)
        output += '%s: Added OSPF nic lo to %s \n' % (current_switch, vrname)
        CHANGED_FLAG.append(True)

    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_current_switch=dict(required=False, type='str'),
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_bgp_as_range=dict(required=False, type='str', default='65000'),
            pn_bgp_redistribute=dict(required=False, type='str',
                                     choices=['none', 'static', 'connected',
                                              'rip', 'ospf'],
                                     default='connected'),
            pn_ospf_redistribute=dict(required=False, type='str',
                                      choices=['none', 'static', 'connected',
                                               'rip', 'ospf'],
                                      default='none'),
            pn_bgp_maxpath=dict(required=False, type='str', default='16'),
            pn_bfd=dict(required=False, type='bool', default=False),
            pn_ibgp_ip_range=dict(required=False, type='str',
                                  default='75.75.75.0/24'),
            pn_ibgp_vlan=dict(required=False, type='str', default='4040'),
            pn_iospf_vlan=dict(required=False, type='str', default='4040'),
            pn_ospf_cost=dict(required=False, type='str', default='10000'),
            pn_iospf_ipv4_range=dict(required=False, type='str',
                                   default='104.255.61.100'),
            pn_cidr_ipv4=dict(required=False, type='str', default='24'),
            pn_subnet_ipv4=dict(required=False, type='str', default='31'),
            pn_iospf_ipv6_range=dict(required=False, type='str',
                                   default='2620:0000:167F:b001::a0'),
            pn_cidr_ipv6=dict(required=False, type='str', default='112'),
            pn_subnet_ipv6=dict(required=False, type='str', default='127'),
            pn_ospf_v4_area_id=dict(required=False, type='str', default='0'),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
            pn_routing_protocol=dict(required=False, type='str',
                                     choices=['ebgp', 'ospf'], default='ebgp'),
            pn_pim_ssm=dict(required=False, type='bool'),
            pn_area_configure_flag=dict(required=False, type='str',
                                        choices=['singlearea', 'dualarea'], default='singlearea'),
            pn_addr_type=dict(required=False, type='str',
                              choices=['ipv4', 'ipv6', 'ipv4_ipv6'], default='ipv4'),
            pn_ospf_v6_area_id=dict(required=False, type='str', default='0.0.0.0'),
        )
    )

    global CHANGED_FLAG
    routing_protocol = module.params['pn_routing_protocol']
    current_switch = module.params['pn_current_switch']
    spine_list = module.params['pn_spine_list']
    message = ''

    # Get the list of vrouter names.
    cli = pn_cli(module)
    cli += ' vrouter-show format name no-show-headers '
    vrouter_names = run_cli(module, cli).split()

    if current_switch in spine_list and spine_list.index(current_switch) == 0:
        message += create_leaf_clusters(module)

    if routing_protocol == 'ebgp':
        dict_bgp_as = find_bgp_as_dict(module)
        message += configure_bgp(module, vrouter_names, dict_bgp_as,
                                 module.params['pn_bgp_maxpath'],
                                 module.params['pn_bgp_redistribute'])
        message += add_bgp_neighbor(module, dict_bgp_as)
        message += assign_ibgp_interface(module, dict_bgp_as)
    elif routing_protocol == 'ospf':
        message += add_ospf_loopback(module, current_switch)
        message += add_ospf_neighbor(module, current_switch)
        message += add_ospf_redistribute(module, current_switch)
        message += make_interface_passive(module, current_switch)
    if current_switch in spine_list and spine_list.index(current_switch) == 0:
        message += assign_leafcluster_ospf_interface(module)

    message_string = message
    results = []
    switch_list = spine_list + module.params['pn_leaf_list']
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
        msg='eBGP/OSPF configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure eBGP/OSPF'
    )

if __name__ == '__main__':
    main()

