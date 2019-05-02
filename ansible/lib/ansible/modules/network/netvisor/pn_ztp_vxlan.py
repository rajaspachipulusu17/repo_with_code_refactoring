#!/usr/bin/python
""" PN CLI VXLAN CONFIGURATION """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli
from collections import OrderedDict

DOCUMENTATION = """
---
module: pn_ztp_vxlan
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: CLI command to configre VXLAN
description: VXLAN configuration for switch setup
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
    pn_tunnel_mode:
      description:
        - Specify type of tunnel mode as either full-mesh or manual.
      required: True
      type: str
      choices: ['full-mesh', 'manual']
      default: 'full-mesh'
    pn_tunnel_vxlan_id:
      description:
        - Specify a number to configure vxlan in tunnel.
      required: False
      type: str
    pn_tunnel_endpoint1:
      description:
        - Specify an endpoint to create a tunnel.
      required: False
      type: str
      default: ''
    pn_tunnel_endpoint2:
      description:
        - Specify an endpoint to create a tunnel.
      required: False
      type: str
      default: ''
    pn_tunnel_overlay_vlan:
      description:
        - Specify overlay vlan.
      required: False
      type: str
    pn_tunnel_loopback_port:
      description:
        - Specify loopback port.
      required: False
      type: str
      default: ''
"""

EXAMPLES = """
- name: Configure VXLAN
  pn_ztp_vxlan:
    pn_spine_list: "{{ groups['spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_tunnel_mode: "full-mesh"
    pn_tunnel_vxlan_id: '4900'
    pn_tunnel_overlay_vlan: '490'
    pn_tunnel_loopback_port: '47'

- name: Configure VXLAN
  pn_ztp_vxlan:
    pn_spine_list: "{{ groups['spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_tunnel_mode: "manual"
    pn_tunnel_endpoint1: "ansible-spine1"
    pn_tunnel_endpoint2: "ansible-leaf1"
    pn_tunnel_vxlan_id: '4900'
    pn_tunnel_overlay_vlan: '490'
    pn_tunnel_loopback_port: '47'
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
            exception=err.strip(),
            summary=results,
            task='Configure VXLAN',
            msg='vxlan configuration failed',
            changed=False
        )
    else:
        return 'Success'


def tunnel_create_for_cluster_nodes(module, switch, peer_switch,
                                    local_ip, remote_ip, tunnel_name):
    """
    Method to find ip of cluster node.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The switch name.
    :param peer_switch: the remote switch.
    :param local_ip: ip of local switch.
    :param remote_ip: ip of peer switch.
    :param tunnel_name: Name of the tunnel.
    :return: String describing if tunnel is created or not.
    """
    global CHANGED_FLAG
    output = ''
    sw_name = switch[:-8]
    cli = pn_cli(module)
    clicopy = cli

    cli += ' tunnel-show format name no-show-headers'
    existing_tunnel_names = list(set(run_cli(module, cli).split()))

    if tunnel_name not in existing_tunnel_names:
        cli = clicopy
        cli += ' switch %s tunnel-create name %s ' % (sw_name, tunnel_name)
        cli += ' scope cluster local-ip %s ' % local_ip
        cli += ' remote-ip %s vrouter-name ' % remote_ip
        cli += ' %s peer-vrouter-name ' % switch
        cli += ' %s ' % (peer_switch[sw_name]+'-vrouter')
        run_cli(module, cli)
        CHANGED_FLAG.append(True)
        output += '%s: Tunnel creation successful for switch \n ' % sw_name

    return output


def tunnel_create_for_nc_nodes(module, switch, local_ip, remote_ip,
                                                         tunnel_name):
    """
    Method to find ip of cluster node.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The switch name.
    :param local_ip: ip of local switch.
    :param remote_ip: ip of peer switch.
    :param tunnel_name: Name of the tunnel.
    :return: String describing if tunnel is created or not.
    """
    output = ''
    sw_name = switch[:-8]
    cli = pn_cli(module)
    clicopy = cli

    cli += ' tunnel-show format name no-show-headers'
    existing_tunnel_names = list(set(run_cli(module, cli).split()))

    if tunnel_name not in existing_tunnel_names:
        cli = clicopy
        cli += ' switch %s tunnel-create name %s ' % (sw_name, tunnel_name)
        cli += ' scope local local-ip %s ' % local_ip
        cli += ' remote-ip %s vrouter-name ' % remote_ip
        cli += ' %s' % switch
        run_cli(module, cli)
        CHANGED_FLAG.append(True)
        output += '%s: Tunnel %s creation ' % (sw_name, tunnel_name)
        output += 'successful \n'

    return output


def add_vxlan_loopback_trunk_ports(module, ports, switch):
    """
    Method to modify the port/ports.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The switch name.
    :return: String describing if port is modified or not.
    """
    output = ''
    cli = pn_cli(module)

    cli += ' switch %s ' % switch
    cli += ' trunk-modify name vxlan-loopback-trunk ports %s' % ports
    out = run_cli(module, cli)
    if out:
        CHANGED_FLAG.append(True)
        output += '%s: Switch successfully modified ' % switch
        output += 'loopback-trunk ports %s \n' % ports

    return output


def add_vxlan_to_tunnel(module, sw_name, vxlan_list, tunnel_name):
    """
    Method to add vxlan to tunnel.
    :param module: The Ansible module to fetch input parameters.
    :param sw_name: The switch name.
    :param vxlan_list: vxlan input list.
    :param tunnel_name: String describing name of the tunnel.
    :return: String describing if port is modified or not.
    """
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    for vxlan in vxlan_list:
        cli = clicopy
        cli += ' switch %s tunnel-vxlan-add ' % sw_name
        cli += ' name  %s '% tunnel_name
        cli += ' vxlan %s ' % vxlan
        if 'Success' in run_cli(module, cli):
            output += '%s: Added VXLAN-ID %s ' % (sw_name, vxlan)
            output += 'to tunnel %s \n ' % tunnel_name

    return output


def create_tunnel(module, full_nodes, cluster_pair):
    """
    Method to create tunnel.
    :param module: The Ansible module to fetch input parameters.
    :param full nodes: node input to create tunnel.
    :return: String describing if tunnel is created or not.
    """
    output = ''
    endpoint1 = module.params['pn_tunnel_endpoint1']
    endpoint2 = module.params['pn_tunnel_endpoint2']
    vxlan_id = module.params['pn_tunnel_vxlan_id'].split(',')
    if endpoint1 and endpoint2:
        all_nodes = {}
        for node in full_nodes:
            if endpoint1+'-vrouter' == node or endpoint2+'-vrouter' == node:
                all_nodes[node] = full_nodes[node]
    else:
        all_nodes = full_nodes

    for node in all_nodes:
        endpoint1 = node[:-8]
        local_ip = all_nodes[node][0]
        is_endpoint1_cluster = all_nodes[node][1]
        for node1 in all_nodes:
            endpoint2 = node1[:-8]
            remote_ip = all_nodes[node1][0]
            is_endpoint2_cluster = all_nodes[node1][1]
            # Ignoring ipv6
            if '.' not in local_ip or '.' not in remote_ip:
                continue
            else:
                # Ignoring same ip configuration
                if  local_ip == remote_ip:
                    pass
                else:
                    if is_endpoint1_cluster is True and is_endpoint2_cluster is False:
                        tunnel_name = endpoint1+'-pair-'+endpoint2
                        output += tunnel_create_for_cluster_nodes(module, node, cluster_pair,
                                                                  local_ip, remote_ip, tunnel_name)
                    elif is_endpoint1_cluster is False and is_endpoint2_cluster is False:
                        tunnel_name = endpoint1+'-'+endpoint2
                        output += tunnel_create_for_nc_nodes(module, node, local_ip,
                                                             remote_ip, tunnel_name)
                    elif is_endpoint1_cluster is False and is_endpoint2_cluster is True:
                        tunnel_name = endpoint1+'-to-'+endpoint2+'-pair'
                        output += tunnel_create_for_nc_nodes(module, node,
                                                             local_ip, remote_ip, tunnel_name)
                    elif is_endpoint1_cluster is True and is_endpoint2_cluster is True:
                        tunnel_name = endpoint1+'-pair-to-'+endpoint2+'-pair'
                        output += tunnel_create_for_cluster_nodes(module, node, cluster_pair,
                                                                  local_ip, remote_ip, tunnel_name)

                    output += add_vxlan_to_tunnel(module, node[:-8], vxlan_id, tunnel_name)
    return all_nodes, output


def find_nodes(module, vlan_id):
    """
    Method to add vxlan to tunnel.
    :param module: The Ansible module to fetch input parameters.
    :param vlan_id: overlay vlan.
    :return: dictionary describing information.
    """
    cli = pn_cli(module)
    clicopy = cli
    all_nodes = OrderedDict()
    cluster_pair = {}

    cli += 'cluster-show format cluster-node-1,cluster-node-2, parsable-delim ,'
    cluster_nodes = run_cli(module, cli).strip().split('\n')
    for cluster in cluster_nodes:
        cluster = cluster.split(',')
        cluster_node1, cluster_node2 = cluster[0], cluster[1]
        cluster_pair[cluster_node2] = cluster_node1
        cluster_pair[cluster_node1] = cluster_node2

    cli = clicopy
    cli += 'vrouter-interface-show vlan %s format ' % vlan_id
    cli += 'ip,is-vip,is-primary,vlan sort-asc vrouter-name parsable-delim ,'
    nodes = run_cli(module, cli).strip().split('\n')
    for node in nodes:
        node = node.split(',')
        vr_name, ip, is_vip, is_primary, vlan = node[0], node[1], node[2], node[3], node[4]
        if '.' in ip:
            if is_primary:
                pass
            elif  is_vip:
                all_nodes[vr_name] = ip, True
            else:
                all_nodes[vr_name] = ip, False

    duplicate_set = set()
    for key in all_nodes.keys():
        value = tuple(all_nodes[key])
        if value in duplicate_set:
            del all_nodes[key]
        else:
            duplicate_set.add(value)

    return all_nodes, cluster_pair


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(argument_spec=dict(
        pn_spine_list=dict(required=False, type='list'),
        pn_leaf_list=dict(required=True, type='list'),
        pn_tunnel_mode=dict(required=False, type='str', default='full-mesh',
                            choices=['full-mesh', 'manual'],
                            required_if=[['pn_tunnel_mode', 'manual',
                                          ['pn_tunnel_endpoint1', 'pn_tunnel_endpoint2'], True]]),
        pn_tunnel_loopback_port=dict(required=False, type='str', default=''),
        pn_tunnel_vxlan_id=dict(required=True, type='str'),
        pn_tunnel_endpoint1=dict(required=False, type='str', default=''),
        pn_tunnel_endpoint2=dict(required=False, type='str', default=''),
        pn_tunnel_overlay_vlan=dict(required=True, type='str'), )
                          )

    output1 = ''
    switch_list = []
    vlan_id = module.params['pn_tunnel_overlay_vlan']
    ports = module.params['pn_tunnel_loopback_port']

    output = ''

    all_nodes, cluster_pair = find_nodes(module, vlan_id)
    all_nodes, output = create_tunnel(module, all_nodes, cluster_pair)
    output1 += output

    spine_list = module.params['pn_spine_list']
    leaf_list =  module.params['pn_leaf_list']
    if spine_list:
        switch_list += spine_list
    if leaf_list:
        switch_list += leaf_list

    for switch in switch_list:
        if ports:
            output1 += add_vxlan_loopback_trunk_ports(module, ports, switch)

    message_string = output1
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

    global CHANGED_FLAG

    module.exit_json(
        unreachable=False,
        task='Configure VXLAN',
        msg='VXLAN configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()
