#!/usr/bin/python
""" PN CLI TUNNEL CONFIGURATION """

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
module: pn_ztp_tunnel
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: CLI command to configre fullmesh tunnel
description: Tunnel configuration for switch setup
options:
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
    pn_csv_data:
      description:
        - CSV File used to configure the l3, vrrp for the fabric.
      required: True
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
"""

EXAMPLES = """
- name: Configure VXLAN
  pn_ztp_tunnel:
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_tunnel_mode: "full-mesh"
    pn_csv_data: 'l3.csv'
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
            task='Configure Tunnel',
            msg='Tunnel configuration failed',
            changed=False
        )
    else:
        return 'Success'



def tunnel_create_for_nc_nodes(module, switch, local_ip, remote_ip,tunnel_name):
    """
    Method to create local tunnel.
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
            if '.' not in local_ip or '.' not in remote_ip:
                continue
            else:
                # Ignoring same ip configuration
                if  local_ip == remote_ip or cluster_pair[endpoint1] == endpoint2:
                    pass
                else:
                    tunnel_name = 'tun-'+endpoint1+'-'+endpoint2
                    output += tunnel_create_for_nc_nodes(module, node, local_ip,
                                                             remote_ip, tunnel_name)
    return output


def find_nodes(module, vlan_id, is_cluster):
    """
    Method to find primary ips of each node.
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
    if is_cluster:
        cli += 'vrouter-interface-show vlan %s is-primary true format ' % vlan_id
        cli += 'ip,is-vip,is-primary,vlan sort-asc vrouter-name parsable-delim ,'
    else:
        cli += 'vrouter-interface-show vlan %s format ' % vlan_id
        cli += 'ip,is-vip,is-primary,vlan sort-asc vrouter-name parsable-delim ,'
    nodes = run_cli(module, cli).strip().split('\n')
    for node in nodes:
        node = node.split(',')
        if len(node) == 5:
            vr_name, ip, is_vip, is_primary, vlan = node[0], node[1], node[2], node[3], node[4]
            if '.' in ip:
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
    module = AnsibleModule(
        argument_spec=dict(
            pn_leaf_list=dict(required=False, type='list'),
            pn_csv_data=dict(required=False, type='str'),
            pn_tunnel_mode=dict(required=False, type='str', default='full-mesh',
                                choices=['full-mesh', 'manual'],
                                required_if=[['pn_tunnel_mode', 'manual',
                                          ['pn_tunnel_endpoint1', 'pn_tunnel_endpoint2'], True]]),
            pn_tunnel_endpoint1=dict(required=False, type='str', default=''),
            pn_tunnel_endpoint2=dict(required=False, type='str', default=''),
        )
    )
    switch_list = []
    vlans = []
    csv_data = module.params['pn_csv_data']
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
                if len(elements) > 4:
                    vlans.append((elements.pop(0).strip(),True))
                else:
                    vlans.append((elements.pop(0).strip(),False))
            else:
                continue
    output = ''
    updated_nodes = OrderedDict()
    for vlan in vlans:
        all_nodes, cluster_pair = find_nodes(module,vlan[0],vlan[1])
        updated_nodes.update(all_nodes)
    output = create_tunnel(module, updated_nodes, cluster_pair)

    switch_list = module.params['pn_leaf_list']

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

    global CHANGED_FLAG

    module.exit_json(
        unreachable=False,
        task='Configure Tunnel',
        msg='Tunnel configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()
