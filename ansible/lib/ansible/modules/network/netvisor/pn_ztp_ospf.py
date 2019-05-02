#!/usr/bin/python
""" PN ZTP OSPF """

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
module: pn_ztp_ospf
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to configure eBGP/OSPF.
description: It performs following steps:
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
    pn_ospf_cidr_ipv4:
      description:
        - Specify CIDR value to be used in configuring IPv4 address.
      required: False
      type: str
    pn_ospf_subnet_ipv4:
      description:
        - Specify subnet value to be used in configuring IPv4 address.
      required: False
      type: str
    pn_cidr_ipv6:
      description:
        - Specify CIDR value to be used in configuring IPv6 address.
      required: False
      type: str
    pn_subnet_ipv6:
      description:
        - Specify subnet value to be used in configuring IPv6 address.
      required: False
      type: str
    pn_routing_protocol:
      description:
        - Specify which routing protocol to specify.
      required: False
      type: str
      choices: ['ospf']
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
      choices=['singlearea', 'multiarea']
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
  pn_ztp_ospf:
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


def add_ospf_neighbor(module, current_switch, dict_area_id, CHANGED_FLAG, task, msg):
    """
    Method to add ospf_neighbor to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_area_id: Dictionary containing area_id of leafs.
    :return: String describing if ospf neighbors got added or not.
    """
    output = ''
    addr_type = module.params['pn_addr_type']
    cli = pn_cli(module)
    cli += ' switch %s ' % current_switch
    clicopy = cli

    vrouter = current_switch + '-vrouter'

    cli = clicopy
    cli += ' vrouter-interface-show vrouter-name %s ' % vrouter
    cli += ' format l3-port no-show-headers '
    port_list = run_command(module, cli, task, msg).split()
    port_list = list(set(port_list))
    port_list.remove(vrouter)

    for port in port_list:
        cli = clicopy
        cli += ' vrouter-interface-show vrouter-name %s l3-port %s' % (
            vrouter, port
        )
        cli += ' format ip no-show-headers'

        ip = run_command(module, cli, task, msg).split()
        ip = list(set(ip))
        ip.remove(vrouter)
        ip = ip[0]
        ip_switch = ip

        if current_switch in module.params['pn_spine_list']:
            cli = clicopy
            cli += 'port-show port %s ' % port
            cli += 'format hostname, no-show-headers'
            hostname = run_command(module, cli, task, msg).split()
            ospf_area_id = dict_area_id[hostname[0]]
        else:
            ospf_area_id = dict_area_id[current_switch]

        if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
            ip = ip.split('.')
            static_part = str(ip[0]) + '.' + str(ip[1]) + '.'
            static_part += str(ip[2]) + '.'
            last_octet = str(ip[3]).split('/')
            netmask = last_octet[1]

            last_octet_ip_mod = int(last_octet[0]) % (1 << (32 - int(netmask)))
            ospf_last_octet = int(last_octet[0]) - last_octet_ip_mod
            ospf_network = static_part + str(ospf_last_octet) + '/' + netmask
        elif addr_type == 'ipv6':
            ip = ip.split('/')
            ip_spine = ip[0]
            netmask = ip[1]
            ip = ip[0]

            ip = ip.split(':')
            if not ip[-1]:
                ip[-1] = '0'
            # leaf_last_octet = hex(int(ip[-1], 16) + 1)[2:]
            last_octet_ipv6 = int(ip[-1], 16)
            last_octet_ipv6_mod = last_octet_ipv6 % (1 << (128 - int(netmask)))
            ospf_last_octet = hex(last_octet_ipv6 - last_octet_ipv6_mod)[2:]
            leaf_last_octet = hex(last_octet_ipv6 + 1)[2:]
            ip[-1] = str(leaf_last_octet)
            ip_leaf = ':'.join(ip)
            ip[-1] = str(ospf_last_octet)
            ospf_network = ':'.join(ip) + '/' + netmask

        if addr_type == 'ipv4_ipv6' or addr_type == 'ipv6':
            cli = clicopy
            cli += ' vrouter-interface-show vrouter-name %s l3-port %s' % (
                vrouter, port)
            if addr_type == 'ipv4_ipv6':
                cli += ' format ip2 no-show-headers'
            elif addr_type == 'ipv6':
                cli += ' format ip no-show-headers'
            ip2 = run_command(module, cli, task, msg).split()
            ip2 = list(set(ip2))
            ip2.remove(vrouter)
            ip_switch_ipv6 = ip2[0]

            cli = clicopy
            cli += 'vrouter-interface-show vrouter-name %s' % vrouter
            if addr_type == 'ipv4_ipv6':
                cli += ' ip2 %s ' % ip_switch_ipv6
            elif addr_type == 'ipv6':
                cli += ' ip %s ' % ip_switch_ipv6
            cli += ' format nic no-show-headers '
            nic = run_command(module, cli, task, msg).split()
            nic = list(set(nic))
            nic.remove(vrouter)
            nic = nic[0]

            cli = clicopy
            cli += 'vrouter-ospf6-show nic %s ' % nic
            cli += 'format switch no-show-headers '
            ipv6_vrouter = run_command(module, cli, task, msg).split()

            if vrouter not in ipv6_vrouter:
                cli = clicopy
                cli += 'vrouter-ospf6-add vrouter-name %s nic %s ospf6-area %s ' % (
                    vrouter, nic, module.params['pn_ospf_v6_area_id'])
                run_command(module, cli, task, msg)
                output += ' %s: Added OSPF6 nic %s to %s \n' % (
                    current_switch, nic, vrouter
                )

        if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
            cli = clicopy
            cli += ' vrouter-ospf-show'
            cli += ' network %s format switch no-show-headers ' % ospf_network
            already_added = run_command(module, cli, task, msg).split()

            if vrouter in already_added:
                pass
            else:
                if module.params['pn_bfd'] is True:
                    CHANGED_FLAG, output1 = configure_ospf_bfd(module, vrouter,
                                                               ip_switch, CHANGED_FLAG, task, msg)
                    output += output1

                cli = clicopy
                cli += ' vrouter-ospf-add vrouter-name ' + vrouter
                cli += ' network %s ospf-area %s' % (ospf_network,
                                                     ospf_area_id)

                if 'Success' in run_command(module, cli, task, msg):
                    output += ' %s: Added OSPF neighbor %s to %s \n' % (
                        current_switch, ospf_network, vrouter
                    )
                    CHANGED_FLAG.append(True)

    return CHANGED_FLAG, output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_current_switch=dict(required=False, type='str'),
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_ospf_redistribute=dict(required=False, type='str',
                                      choices=['none', 'static', 'connected',
                                               'rip', 'bgp'],
                                      default='none'),
            pn_bfd=dict(required=False, type='bool', default=False),
            pn_iospf_vlan=dict(required=False, type='str', default='4040'),
            pn_ospf_cost=dict(required=False, type='str', default='10000'),
            pn_iospf_ipv4_range=dict(required=False, type='str',
                                     default='75.75.75.1'),
            pn_ospf_cidr_ipv4=dict(required=False, type='str', default='24'),
            pn_ospf_subnet_ipv4=dict(required=False, type='str', default='31'),
            pn_iospf_ipv6_range=dict(required=False, type='str',
                                     default=''),
            pn_cidr_ipv6=dict(required=False, type='str', default='112'),
            pn_subnet_ipv6=dict(required=False, type='str', default='127'),
            pn_ospf_v4_area_id=dict(required=False, type='str', default='0'),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
            pn_routing_protocol=dict(required=False, type='str',
                                     choices=['ospf'], default='ospf'),
            pn_pim_ssm=dict(required=False, type='bool', default=False),
            pn_area_configure_flag=dict(required=False, type='str',
                                        choices=['singlearea', 'multiarea'],
                                        default='singlearea'),
            pn_addr_type=dict(required=False, type='str',
                              choices=['ipv4', 'ipv6', 'ipv4_ipv6'],
                              default='ipv4'),
            pn_ospf_v6_area_id=dict(required=False, type='str',
                                    default='0.0.0.0'),
        )
    )

    global CHANGED_FLAG
    routing_protocol = module.params['pn_routing_protocol']
    current_switch = module.params['pn_current_switch']
    spine_list = module.params['pn_spine_list']
    message = ''

    global task
    global msg

    task = 'Configure OSPF',
    msg = 'L3 OSPF configuration failed'

    if current_switch in spine_list and spine_list.index(current_switch) == 0:
        CHANGED_FLAG, output1 = create_leaf_clusters(module, CHANGED_FLAG, task, msg)
        message += output1

    if routing_protocol == 'ospf':
        dict_area_id = find_area_id_leaf_switches(module, task, msg)
        CHANGED_FLAG, output1 = add_ospf_loopback(module, current_switch, CHANGED_FLAG, task, msg)
        message += output1
        CHANGED_FLAG, output1 = add_ospf_neighbor(module, current_switch, dict_area_id, CHANGED_FLAG, task, msg)
        message += output1
        CHANGED_FLAG, output1 = add_ospf_redistribute(module, current_switch, CHANGED_FLAG, task, msg)
        message += output1
        CHANGED_FLAG, output1 = make_interface_passive(module, current_switch, CHANGED_FLAG, task, msg)
        message += output1
    if current_switch in spine_list and spine_list.index(current_switch) == 0:
        CHANGED_FLAG, output1 = assign_leafcluster_ospf_interface(module, dict_area_id, current_switch, CHANGED_FLAG, task, msg)
        message += output1

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
        msg='OSPF configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure OSPF'
    )


if __name__ == '__main__':
    main()
