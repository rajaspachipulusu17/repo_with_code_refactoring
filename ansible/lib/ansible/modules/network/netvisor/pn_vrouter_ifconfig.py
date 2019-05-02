#!/usr/bin/python
""" PN-CLI vrouter-interface-config-add/remove/modify """
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


DOCUMENTATION = """
---
module: pn_vrouter_ifconfig
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove/modify vrouter-interface-config.
description:
  - Execute vrouter-interface-config-add, vrouter-interface-config-remove,
    vrouter-interface-config-modify command.
  - You can add/remove/modify interface configurations to/from
    vRouter services.
options:
  pn_cliusername:
    description:
      - Provide login username if user is not root.
    required: False
    type: str
  pn_clipassword:
    description:
      - Provide login password if user is not root.
    required: False
    type: str
  pn_cliswitch:
    description:
      - Target switch to run the cli on.
    required: False
    type: str
  pn_action:
    description:
      - vRouter interface config command.
    required: True
    choices: ['add', 'remove','modify']
    type: str
  pn_vrouter:
    description:
      - Name of the vRouter.
    required: True
    type: str
  pn_nic:
    description:
      - Virtual NIC name.
    required: True
    type: str
  pn_ospf_hello_int:
    description:
      - OSPF hello interval from 1 to 65535, default 10.
    type: str
  pn_osfp_dead_int:
    description:
      - OSPF dead interval from 2 to 65535, default 5.
    type: str
  pn_ospf_priorty:
    description:
      - OSPF priority from 0 to 255, default 1.
    type: str
  pn_ospf_authkey:
    description:
      - OSPF authentication key.
    type: str
  pn_ospf_cost:
    description:
      - OSPF Cost.
    type: str
  pn_ospf_msg_digestid:
    description:
      - OSPF digest ID from 0 to 255. Requires pn_ospf_msg_digestkey.
    type: str
  pn_ospf_msg_digestkey:
    description:
      - OSPF MSG digest key. Requires pn_ospf_msg_digestid.
    type: str
  pn_ospf_passive_if:
    description:
      - OSPF passive interface.
    type: bool
  pn_ospf_network_type:
    description:
      - OSPF network type.
    type: str
    choices: ['default', 'point-to-point']
  pn_ospf_bfd
    description:
      - BFD protocol support for OSPF fault detection.
    type: str
    choices: ['default', 'enable', 'disable']
  pn_bfd_interval:
    description:
      - BFD desired transmit interval from 200ms to 3000ms, default 750ms.
    type: str
  pn_bfd_min_rx:
    description:
      - BFD desired minimum receive interval from 200ms to 3000ms, default
        500ms.
    type: str
  pn_bfd_multiplier:
    description:
      - BFD detection multiplier from 1 to 20, default 3.
    type: str
  pn_nd_suppress_ra:
    description:
      - Control transmit of IPv6 Router Advertisements.
    type: bool
  pn_v6_ra_prefix:
    description:
      - IPv6 prefix to include in Router Advertisement.
    type: str
  pn_prefix_netmask:
    description:
      - v6 prefix netmask.
    type: str
  pn_autoconf:
    description:
      - Given prefix can be used for IPv6 autoconf.
    type: bool
  pn_ra_interval:
    description:
      - Time interval between ipv6 router advertisements.
    type: str
  pn_ra_lifetime:
    description:
      - Time for which router is considered as default router.
    type: str
"""

EXAMPLES = """
- name: Add vrouter interface config
  pn_vrouter_ifconfig:
    pn_cliusername: admin
    pn_clipassword: admin
    pn_action: 'add'
    pn_vrouter: 'ansible-vrouter'
    pn_nic: 'eth1.101'
    pn_ospf_hello_int: 10
    pn_ospf_dead_int: 5
    pn_ospf_bfd: enable
    pn_autoconf: False

- name: Remove vrouter interface config
  pn_vrouter_if_config:
    pn_cliusername: admin
    pn_clipassword: admin
    pn_action: 'remove'
    pn_vrouter: 'ansible-vrouter'
    pn_nic: 'eth1.101'

- name: Modify vrouter interface config
  pn_vrouter_ifconfig:
    pn_cliusername: admin
    pn_clipassword: admin
    pn_action: 'modify'
    pn_vrouter: 'ansible-vrouter'
    pn_nic: 'eth1.101'
    pn_ospf_hello_int: 20
    pn_ospf_dead_time: 10
    pn_autocpnf: True
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter interface
  config command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter
  interface config command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the
  target.
  returned: always
  type: bool
"""


VROUTER_EXISTS = None
NIC_EXISTS = None
VRRP_EXISTS = None


def pn_cli(module):
    """
    This method is to generate the cli portion to launch the Netvisor cli.
    It parses the username, password, switch parameters from module.
    :param module: The Ansible module to fetch username, password and switch
    :return: returns the cli string for further processing
    """
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    cliswitch = module.params['pn_cliswitch']

    if username and password:
        cli = '/usr/bin/cli --quiet --user "%s":"%s" ' % (username, password)
    else:
        cli = '/usr/bin/cli --quiet '

    if cliswitch:
        cli += ' switch ' + cliswitch

    return cli


def check_cli(module):
    """
    This method checks for idempotency.
    If the given vRouter exists, return VROUTER_EXISTS as True else False.

    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VROUTER_EXISTS, NIC_EXISTS
    """
    vrouter = module.params['pn_vrouter']
    nic = module.params['pn_nic']
    show_cli = pn_cli(module)

    # Global flags
    global VROUTER_EXISTS, NIC_EXISTS

    cliswitch = module.params['pn_cliswitch']
    if cliswitch:
        show_cli = show_cli.replace('switch ', '')
        show_cli = show_cli.replace(cliswitch, '')

    # Check for vRouter
    check_vrouter = show_cli + ' vrouter-show format name no-show-headers '
    check_vrouter = shlex.split(check_vrouter)
    out = module.run_command(check_vrouter)[1]
    out = out.split()

    VROUTER_EXISTS = True if vrouter in out else False

    # Check for nic
    check_nic = show_cli + ' vrouter-interface-config-show ' \
                           ' vrouter-name %s ' % vrouter
    check_nic += ' nic %s format nic no-show-headers' % nic
    check_nic = shlex.split(check_nic)
    out = module.run_command(check_nic)[1]
    NIC_EXISTS = True if nic in out else False


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
            msg="vRouter interface config %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vRouter interface config %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vRouter interface config %s operation completed" % action,
            changed=True
        )


def main():
    """ This portion is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove', 'modify']),
            pn_vrouter=dict(required=True, type='str'),
            pn_nic=dict(required=True, type='str'),
            pn_ospf_hello_int=dict(type='str'),
            pn_ospf_dead_int=dict(type='str'),
            pn_ospf_priority=dict(type='str'),
            pn_ospf_authkey=dict(type='str'),
            pn_ospf_cost=dict(type='str'),
            pn_ospf_msg_digestid=dict(type='str'),
            pn_ospf_msg_digestkey=dict(type='str'),
            pn_ospf_passive_if=dict(type='bool'),
            pn_ospf_network_type=dict(type='str',
                                      choices=['default', 'point-to-point']),
            pn_ospf_bfd=dict(type='str',
                             choices=['default', 'enable', 'disable']),
            pn_bfd_interval=dict(type='str'),
            pn_bfd_min_rx=dict(type='str'),
            pn_bfd_multiplier=dict(type='str'),
            pn_nd_suppress_ra=dict(type='bool'),
            pn_v6_ra_prefix=dict(type='str'),
            pn_prefix_netmask=dict(type='str'),
            pn_autoconf=dict(type='str'),
            pn_ra_interval=dict(type='str'),
            pn_ra_lifetime=dict(type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vrouter-interface-config-' + action
    vrouter = module.params['pn_vrouter']
    nic = module.params['pn_nic']
    ospf_hello_int = module.params['pn_ospf_hello_int']
    ospf_dead_int = module.params['pn_ospf_dead_int']
    ospf_priority = module.params['pn_ospf_priority']
    ospf_authkey = module.params['pn_ospf_authkey']
    ospf_cost = module.params['pn_ospf_cost']
    ospf_msg_digestid = module.params['pn_ospf_msg_digestid']
    ospf_msg_digestkey = module.params['pn_ospf_msg_digestkey']
    ospf_passive_if = module.params['pn_ospf_passive_if']
    ospf_network_type = module.params['pn_ospf_network_type']
    ospf_bfd = module.params['pn_ospf_bfd']
    bfd_interval = module.params['pn_bfd_interval']
    bfd_min_rx = module.params['pn_bfd_min_rx']
    bfd_multiplier = module.params['pn_bfd_multiplier']
    nd_suppress_ra = module.params['pn_nd_suppress_ra']
    v6_ra_prefix = module.params['pn_v6_ra_prefix']
    prefix_netmask = module.params['pn_prefix_netmask']
    autoconf = module.params['pn_autoconf']
    ra_interval = module.params['pn_ra_interval']
    ra_lifetime = module.params['pn_ra_lifetime']

    # Building the CLI command string
    cli = pn_cli(module)

    check_cli(module)

    cli += ' %s vrouter-name %s nic %s ' % (command, vrouter, nic)
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

    else:
        if action == 'add':
            if VROUTER_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter %s does not exist' % vrouter
                )
            if NIC_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='vRouter interface with nic %s already exists' % nic
                )

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

        if ospf_hello_int:
            cli += ' ospf-hello-interval ' + ospf_hello_int

        if ospf_dead_int:
            cli += ' ospf-dead-interval ' + ospf_dead_int

        if ospf_priority:
            cli += ' ospf-priority ' + ospf_priority

        if ospf_authkey:
            cli += ' ospf-auth-key ' + ospf_authkey

        if ospf_cost:
            cli += ' ospf-cost ' + ospf_cost

        if ospf_msg_digestid:
            cli += ' ospf-msg-digest-id ' + ospf_msg_digestid
            cli += ' ospf-msg-digest-key ' + ospf_msg_digestkey

        if ospf_passive_if is True:
            cli += ' ospf-passive-if '
        if ospf_passive_if is False:
            cli += ' no-ospf-passive-if '

        if ospf_network_type:
            cli += ' ospf-network-type ' + ospf_network_type

        if ospf_bfd:
            cli += ' ospf-bfd ' + ospf_bfd

        if bfd_interval:
            cli += ' bfd-interval ' + bfd_interval

        if bfd_min_rx:
            cli += ' bfd-min-rx ' + bfd_min_rx

        if bfd_multiplier:
            cli += ' bfd-multiplier ' + bfd_multiplier

        if nd_suppress_ra is True:
            cli += ' nd-suppress-ra '
        if nd_suppress_ra is False:
            cli += ' no-nd-suppress-ra '

        if v6_ra_prefix:
            cli += ' v6-ra-prefix ' + v6_ra_prefix

        if prefix_netmask:
            cli += ' prefix-netmask ' + prefix_netmask

        if autoconf is True:
            cli += ' autoconf '
        if autoconf is False:
            cli += ' no-autoconf '

        if ra_interval:
            cli += ' ra-interval ' + ra_interval

        if ra_lifetime:
            cli += ' ra-lifetime ' + ra_lifetime

    run_cli(module, cli)

if __name__ == '__main__':
    main()
