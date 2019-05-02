#!/usr/bin/python
""" PN-CLI vrouter-interface-add/remove/modify """
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


DOCUMENTATION = """
---
module: pn_vrouter_iface
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove/modify vrouter-interface.
description:
  - Execute vrouter-interface-add, vrouter-interface-remove,
    vrouter-interface-modify command.
  - You can configure interfaces to vRouter services on a fabric, cluster,
    standalone switch or virtual network(VNET).
options:
  pn_action:
    description:
      - vRouter interface command.
    required: True
    choices: ['add', 'remove','modify']
    type: str
  pn_vrouter:
    description:
      - Name of the vRouter.
    required: True
    type: str
  pn_vlan:
    description:
      - Interface VLAN.
    type: str
  pn_vlan_type:
    description:
      - Interface VLAN type.
    type: str
    choices: ['public', 'private']
  pn_interface_ip:
    description:
      - IP address for the interface in x.x.x.x/n format.
    type: str
  pn_assignment:
    description:
      - Type of IP address assignment.
    choices:['none', 'dhcp', 'dhcpv6', 'autov6']
    type: str
  pn_vnet:
    description:
      - Interface vLAN VNET.
    type: str
  pn_interface:
    description:
      - Interface type management, data or span interface.
    choices: ['mgmt', 'data', 'span']
    type: str
  pn_alias:
    description:
      - Specify an alias name for the interface.
    type: str
  pn_exclusive:
    description:
      - Specify if the interface is exclusive to the configuration.
    type: bool
  pn_nic_state:
    description:
      - NIC config.
    type: str
    choices: ['enable', 'disable']
  pn_vrrp_primary:
    description:
      - VRRP primary interface.
    type: str
  pn_vrrp_id:
    description:
      - ID assigned to VRRP interface.
    type: str
  pn_vrrp_priority:
    description:
      - Speicfies the priority for the VRRP interface. This is a value
        between 1 (lowest) and 255 (highest).
    type: int
  pn_vrrp_adv_int:
    description:
      - Specify a VRRP advertisement interval in milliseconds. The range is
        from 30 to 40950 with a default value of 1000.
    type: str
  pn_l3port:
    description:
      - Specify a Layer 3 port for the interface.
    type: str
  pn_secondary_macs:
    description:
      - Specify a secondary MAC address for the interface.
    type: str
  pn_nic:
    description:
      - Virtual NIC assigned to interface.
        Used for vrouter-interface remove/modify.
    type: str
  pn_mtu:
    description:
      - Interface MTU.
    type: str
  pn_if_nat_realm:
    description:
      - NAT interface realm.
    type: str
    choices: ['internal, 'external']
"""

EXAMPLES = """
- name: Add vrouter-interface
  pn_vrouter_iface:
    pn_action: 'add'
    pn_vrouter: 'ansible-vrouter'
    pn_interface_ip: 101.101.101.2/24
    pn_vlan: 101

- name: Add VRRP to the above added interface
  pn_vrouter_iface:
    pn_action: 'add'
    pn_vrouter: 'ansible-vrouter'
    pn_interface_ip: 101.101.101.2/24
    pn_vrrp_ip: 101.101.101.1/24
    pn_vrrp_priority: 100
    pn_vlan: 101

- name: Remove vrouter-interface
  pn_vrouter_iface:
    pn_action: 'remove'
    pn_vrouter: 'ansible-vrouter'
    pn_nic: 'eth1.101'

- name: Modify vrouter-interface
  pn_vrouter_iface:
    pn_action: modify
    pn_vrouter: 'ansible-vrouter'
    pn_nic: 'eth1.101'
    pn_mtu: 1500
    pn_if_nat_realm: internal
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter interface
  command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter
  interface command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the
  target.
  returned: always
  type: bool
"""


VROUTER_EXISTS = None
INTERFACE_EXISTS = None
NIC_EXISTS = None
VRRP_EXISTS = None


def check_cli(module):
    """
    This method checks if vRouter exists on the target node.
    This method also checks for idempotency using the vrouter-interface-show
    command.
    If the given vRouter exists, return VROUTER_EXISTS as True else False.

    If an interface with the given ip exists on the given vRouter,
    return INTERFACE_EXISTS as True else False. This is required for
    vrouter-interface-add.

    If nic exists on the given vRouter, return NIC_EXISTS as True else
    False. This is required for vrouter-interface-remove.

    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VROUTER_EXISTS, INTERFACE_EXISTS, NIC_EXISTS
    """
    vrouter = module.params['pn_vrouter']
    interface_ip = module.params['pn_interface_ip']
    nic = module.params['pn_nic']
    show_cli = pn_cli(module)
    # Global flags
    global VROUTER_EXISTS, INTERFACE_EXISTS, NIC_EXISTS

    # Check for vRouter
    check_vrouter = show_cli + ' vrouter-show format name no-show-headers '
    check_vrouter = shlex.split(check_vrouter)
    out = module.run_command(check_vrouter)[1]
    out = out.split()

    VROUTER_EXISTS = True if vrouter in out else False

    if interface_ip:
        # Check for interface and VRRP and fetch nic for VRRP
        show = show_cli + ' vrouter-interface-show vrouter-name %s ' % vrouter
        show += 'ip %s format ip,nic no-show-headers' % interface_ip
        show = shlex.split(show)
        out = module.run_command(show)[1]
        INTERFACE_EXISTS = True if out else False

    if nic:
        # Check for nic
        show = show_cli + ' vrouter-interface-show vrouter-name %s ' % vrouter
        show += ' format nic no-show-headers'
        show = shlex.split(show)
        out = module.run_command(show)[1]
        NIC_EXISTS = True if nic in out else False


def get_nic(module):
    """
    This module checks if VRRP interface can be added. If No,
    return VRRP_EXISTS as True.
    If Yes, fetch the nic string from the primary interface and return nic and
    VRRP_EXISTS as False.
    :param module: The Ansible module to fetch input parameters
    :return: nic, Global Boolean: VRRP_EXISTS
    """
    vrouter = module.params['pn_vrouter']
    interface_ip = module.params['pn_interface_ip']
    vrrp_primary = module.params['pn_vrrp_primary']
    show_cli = pn_cli(module)

    global VRRP_EXISTS

    # Check for interface and VRRP and fetch nic for VRRP
    show = show_cli + ' vrouter-interface-show vrouter-name %s ' % vrouter
    show += 'ip %s format ip,nic no-show-headers' % interface_ip
    show = shlex.split(show)
    out = module.run_command(show)[1]
    out = out.split()

    if len(out) > 3:
        VRRP_EXISTS = True
        return None
    else:
        nic = out[2]
        VRRP_EXISTS = False
        if vrrp_primary:
            return vrrp_primary
        else:
            return nic


def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    action = module.params['pn_action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="vRouter interface %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vRouter interface %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vRouter interface %s operation completed" % action,
            changed=True
        )


def main():
    """ This portion is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove', 'modify']),
            pn_vrouter=dict(required=True, type='str'),
            pn_vlan=dict(type='str'),
            pn_interface_ip=dict(required=True, type='str'),
            pn_assignment=dict(type='str',
                               choices=['none', 'dhcp', 'dhcpv6', 'autov6']),
            pn_vnet=dict(type='str'),
            pn_vlan_type=dict(type='str',
                              choices=['public', 'private']),
            pn_interface=dict(type='str',
                              choices=['mgmt', 'data', 'span']),
            pn_alias=dict(type='str'),
            pn_exclusive=dict(type='bool'),
            pn_nic_state=dict(type='str',
                              choices=['enable', 'disable']),
            pn_vrrp_id=dict(type='str'),
            pn_vrrp_primary=dict(type='str'),
            pn_vrrp_priority=dict(type='str'),
            pn_vrrp_adv_int=dict(type='str'),
            pn_l3port=dict(type='str'),
            pn_secondary_macs=dict(type='str'),
            pn_mtu=dict(type='str'),
            pn_nic=dict(type='str'),
            pn_if_nat_realm=dict(type='str',
                                 choices=['internal', 'external'])
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vrouter-interface-' + action
    vrouter = module.params['pn_vrouter']
    vlan = module.params['pn_vlan']
    interface_ip = module.params['pn_interface_ip']
    assignment = module.params['pn_assignment']
    vnet = module.params['pn_vnet']
    vlan_type = module.params['pn_vlan_type']
    interface = module.params['pn_interface']
    alias = module.params['pn_alias']
    exclusive = module.params['pn_exclusive']
    nic_state = module.params['pn_nic_state']
    vrrp_id = module.params['pn_vrrp_id']
    vrrp_primary = module.params['pn_vrrp_primary']
    vrrp_priority = module.params['pn_vrrp_priority']
    vrrp_adv_int = module.params['pn_vrrp_adv_int']
    l3port = module.params['pn_l3port']
    secondary_macs = module.params['pn_secondary_macs']
    nic = module.params['pn_nic']
    mtu = module.params['pn_mtu']
    if_nat_realm = module.params['pn_if_nat_realm']

    # Building the CLI command string
    cli = pn_cli(module)

    check_cli(module)

    if action == 'remove':
        if VROUTER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter %s does not exist' % vrouter
            )
        if NIC_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter interface with nic %s does not exist' % nic
            )
        cli += ' %s vrouter-name %s nic %s ' % (command, vrouter, nic)

    else:
        if action == 'add':
            if VROUTER_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter %s does not exist' % vrouter
                )

            if vrrp_id:
                vrrp_primary = get_nic(module)
                if VRRP_EXISTS is True:
                    module.exit_json(
                        skipped=True,
                        msg=('VRRP interface on %s already exists. Check '
                             'the IP addresses' % vrouter)
                    )
                cli += ' %s vrouter-name %s ' % (command, vrouter)
                cli += (' ip %s vrrp-primary %s vrrp-id %s '
                        % (interface_ip, vrrp_primary, vrrp_id))
                if vrrp_priority:
                    cli += ' vrrp-priority ' + vrrp_priority
                if vrrp_adv_int:
                    cli += ' vrrp-adv-int ' + vrrp_adv_int

            else:
                if INTERFACE_EXISTS is True:
                    module.exit_json(
                        skipped=True,
                        msg=('vRouter interface on %s already exists. '
                             'Check the IP address(es)' % vrouter)
                    )
                cli += ' %s vrouter-name %s ' % (command, vrouter)
                cli += ' ip %s ' % interface_ip

        if action == 'modify':
            if VROUTER_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter %s does not exist' % vrouter
                )
            if NIC_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter interface with nic %s does not exist' % nic
                )
            cli += ' %s vrouter-name %s nic %s ' % (command, vrouter, nic)
            if vrrp_primary:
                cli += ' vrrp-primary ' + vrrp_primary
            if vrrp_priority:
                cli += ' vrrp-priority ' + vrrp_priority
            if vrrp_adv_int:
                cli += ' vrrp-adv-int ' + vrrp_adv_int

        if vlan:
            cli += ' vlan ' + vlan

        if vlan_type:
            cli += ' vlan-type ' + vlan_type

        if l3port:
            cli += ' l3-port ' + l3port

        if assignment:
            cli += ' assignment ' + assignment

        if vnet:
            cli += ' vnet ' + vnet

        if interface:
            cli += ' if ' + interface

        if alias:
            cli += ' alias-on ' + alias

        if exclusive is True:
            cli += ' exclusive '
        if exclusive is False:
            cli += ' no-exclusive '

        if nic_state:
            cli += ' nic-' + nic_state

        if secondary_macs:
            cli += ' secondary-macs ' + secondary_macs

        if mtu:
            cli += ' mtu ' + mtu

        if if_nat_realm:
            cli += ' if-nat-realm ' + if_nat_realm

    run_cli(module, cli)

if __name__ == '__main__':
    main()
