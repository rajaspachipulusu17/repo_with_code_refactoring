#!/usr/bin/python
""" PN CLI EBGP """

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
module: pn_ztp_ebgp
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
    pn_ibgp_cidr_ipv4:
      description:
        - Specify CIDR value to be used in configuring IPv4 address.
      required: False
      type: str
    pn_ibgp_subnet_ipv4:
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
      choices: ['ebgp']
    pn_ibgp_ipv4_range:
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
    pn_jumbo_frames:
      description:
        - Flag to assign mtu
      required: False
      default: False
      type: bool
"""

EXAMPLES = """
- name: Configure eBGP
  pn_ztp_ebgp:
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


def add_bgp_neighbor(module, dict_bgp_as, CHANGED_FLAG, task, msg):
    """
    Method to add bgp_neighbor to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: Dictionary containing bgp-as of all switches.
    :return: String describing if bgp neighbors got added or not.
    """
    output = ''
    cli = pn_cli(module)
    addr_type = module.params['pn_addr_type']
    clicopy = cli

    spine_dict = dict()
    for spine in module.params['pn_spine_list']:
        spine_dict[spine] = list()

    for leaf in module.params['pn_leaf_list']:
        leaf_input = list()
        cli = clicopy
        cli += ' vrouter-show location %s' % leaf
        cli += ' format name no-show-headers'
        vrouter_leaf = run_command(module, cli, task, msg).split()[0]

        cli = clicopy
        cli += 'vrouter-interface-show vrouter-name %s ' % vrouter_leaf
        cli += 'format l3-port,ip,'
        if addr_type == 'ipv4_ipv6':
            cli += 'ip2'
        cli += ' parsable-delim ,'
        vr_leaf_out = run_command(module, cli, task, msg).strip().split('\n')
        for vr in vr_leaf_out:
            vr = vr.strip().split(',')
            if vr[1]:
                leaf_input.append(vr)

        count = 0
        for spine in module.params['pn_spine_list']:
            spine_dict[spine].append(leaf_input[count])
            count += 1

    for spine in module.params['pn_spine_list']:
        for bgp_neighbor in spine_dict[spine]:
            cli = clicopy
            cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
            cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[2]
            already_added = run_command(module, cli, task, msg).split()

            if spine+'-vrouter' in already_added:
                output += ''
            else:
                cli = clicopy
                cli += ' vrouter-bgp-add vrouter-name ' + spine + '-vrouter'
                cli += ' neighbor %s remote-as %s ' % (bgp_neighbor[2],
                                                       dict_bgp_as[bgp_neighbor[0][:-8]])
                if module.params['pn_bfd']:
                    cli += ' bfd '

                if 'Success' in run_command(module, cli, task, msg):
                    output += ' %s: Added BGP Neighbor %s for %s \n' % (
                        spine, bgp_neighbor[1], spine+'vrouter'
                    )
                    CHANGED_FLAG.append(True)

            if addr_type == 'ipv4_ipv6':
                cli = clicopy
                cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
                cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[3]
                already_added = run_command(module, cli, task, msg).split()

                if spine+'-vrouter' in already_added:
                    output += ''
                else:
                    cli = clicopy
                    cli += ' vrouter-bgp-add vrouter-name ' + spine + '-vrouter'
                    cli += ' neighbor %s remote-as %s ' % (bgp_neighbor[3],
                                                           dict_bgp_as[bgp_neighbor[0][:-8]])
                    cli += ' multi-protocol ipv6-unicast'
                    if module.params['pn_bfd']:
                        cli += ' bfd '

                    if 'Success' in run_command(module, cli, task, msg):
                        output += ' %s: Added BGP Neighbor %s for %s \n' % (
                            spine, bgp_neighbor[1], spine+'vrouter'
                        )
                        CHANGED_FLAG.append(True)

    leaf_dict = dict()
    for leaf in module.params['pn_leaf_list']:
        leaf_dict[leaf] = list()

    for spine in module.params['pn_spine_list']:
        spine_input = list()
        cli = clicopy
        cli += ' vrouter-show location %s' % spine
        cli += ' format name no-show-headers'
        vrouter_spine = run_command(module, cli, task, msg).split()[0]

        cli = clicopy
        cli += 'vrouter-interface-show vrouter-name %s ' % vrouter_spine
        cli += 'format l3-port,ip,ip2 parsable-delim ,'
        vr_spine_out = run_command(module, cli, task, msg).strip().split('\n')

        for vr in vr_spine_out:
            vr = vr.strip().split(',')
            if vr[1]:
                spine_input.append(vr)

        count = 0
        for leaf in module.params['pn_leaf_list']:
            leaf_dict[leaf].append(spine_input[count])
            count += 1

    for leaf in module.params['pn_leaf_list']:
        for bgp_neighbor in leaf_dict[leaf]:
            cli = clicopy
            cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
            cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[2]
            already_added = run_command(module, cli, task, msg).split()

            if leaf+'-vrouter' in already_added:
                output += ''
            else:
                cli = clicopy
                cli += ' vrouter-bgp-add vrouter-name ' + leaf + '-vrouter'
                cli += ' neighbor %s remote-as %s ' % (bgp_neighbor[2],
                                                       dict_bgp_as[bgp_neighbor[0][:-8]])
                if module.params['pn_bfd']:
                    cli += ' bfd '

                if 'Success' in run_command(module, cli, task, msg):
                    output += ' %s: Added BGP Neighbor %s for %s \n' % (
                        leaf, bgp_neighbor[1], leaf+'-vrouter'
                    )
                    CHANGED_FLAG.append(True)

            if addr_type == 'ipv4_ipv6':
                cli = clicopy
                cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
                cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[3]
                already_added = run_command(module, cli, task, msg).split()

                if leaf+'-vrouter' in already_added:
                    output += ''
                else:
                    cli = clicopy
                    cli += ' vrouter-bgp-add vrouter-name ' + leaf + '-vrouter'
                    cli += ' neighbor %s remote-as %s' % (bgp_neighbor[3],
                                                          dict_bgp_as[bgp_neighbor[0][:-8]])
                    cli += ' multi-protocol ipv6-unicast'
                    if module.params['pn_bfd']:
                        cli += ' bfd '

                    if 'Success' in run_command(module, cli, task, msg):
                        output += ' %s: Added BGP Neighbor %s for %s \n' % (
                            leaf, bgp_neighbor[1], leaf+'-vrouter'
                        )
                        CHANGED_FLAG.append(True)

    return CHANGED_FLAG, output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_addr_type=dict(required=False, type='str',
                              choices=['ipv4', 'ipv4_ipv6', 'ipv6'], default='ipv4'),
            pn_bgp_as_range=dict(required=False, type='str', default='65000'),
            pn_bgp_redistribute=dict(required=False, type='str',
                                     choices=['none', 'static', 'connected',
                                              'rip', 'ospf'],
                                     default='none'),
            pn_bgp_maxpath=dict(required=False, type='str', default='16'),
            pn_ibgp_ipv4_range=dict(required=False, type='str',
                                    default='75.75.75.1'),
            pn_ibgp_cidr_ipv4=dict(required=False, type='str', default='24'),
            pn_ibgp_subnet_ipv4=dict(required=False, type='str', default='31'),
            pn_ibgp_ipv6_range=dict(required=False, type='str'),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
            pn_pim_ssm=dict(required=False, type='bool', default=False),
            pn_cidr_ipv6=dict(required=False, type='str', default='112'),
            pn_subnet_ipv6=dict(required=False, type='str', default='127'),
            pn_bfd=dict(required=False, type='bool', default=False),
            pn_ibgp_vlan=dict(required=False, type='str', default='4040'),
            pn_routing_protocol=dict(required=False, type='str',
                                     choices=['ebgp'], default='ebgp'),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Configure BGP',
    msg = 'L3 BGP configuration failed'

    routing_protocol = module.params['pn_routing_protocol']
    message = ''

    # Get the list of vrouter names.
    cli = pn_cli(module)
    cli += ' vrouter-show format name no-show-headers '
    vrouter_names = run_command(module, cli, task, msg).split()

    CHANGED_FLAG, message = create_leaf_clusters(module, CHANGED_FLAG, task, msg)

    if routing_protocol == 'ebgp':
        dict_bgp_as = find_bgp_as_dict(module, task, msg)
        CHANGED_FLAG, output = configure_bgp(module, vrouter_names, dict_bgp_as,
                                             module.params['pn_bgp_maxpath'],
                                             module.params['pn_bgp_redistribute'],
                                             CHANGED_FLAG, task, msg)
        message += output
        CHANGED_FLAG, output = add_bgp_neighbor(module, dict_bgp_as, CHANGED_FLAG, task, msg)
        message += output
        CHANGED_FLAG, output = assign_ibgp_interface(module, dict_bgp_as, CHANGED_FLAG, task, msg)
        message += output

    message_string = message
    results = []
    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']
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
        msg='eBGP configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure eBGP'
    )


if __name__ == '__main__':
    main()
