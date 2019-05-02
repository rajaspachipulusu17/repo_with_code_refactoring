#!/usr/bin/python
""" PN-CLI vrouter-static-route-add/remove """
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
module: pn_vrouter_static
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove static routes to/from a vRouter.
description:
  - Execute vrouter-static-route-add, vrouter-static-route-remove command.
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
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - vRouter static route config command.
    required: True
    choices: ['add', 'remove']
    type: str
  pn_vrouter:
    description:
      - Name of the vRouter.
    required: True
    type: str
  pn_network:
    description:
      - Specify the network IP address.
    required: True
    type: str
  pn_netmask:
    description:
      - Specify the netmask.
    type: str
  pn_gateway:
    description:
      - Gateway IP address.
    type: str
  pn_bfd_dst:
    description:
      - Destination IP address for BFD monitoring.
    type: str
  pn_distance:
    description:
      - Distance assigned to route from 1 to 255.
    type: str
"""

EXAMPLES = """
- name: "Add static route to vrouter"
  pn_vrouter_static:
    pn_action: add
    pn_vrouter: ansible-vrouter
    pn_network: 192.168.11.2
    pn_netmask: 255.255.255.0
    pn_gateway: 10.9.9.1
    pn_bfd_dst: 192.168.12.2
    pn_distance: 10

- name: "Remove static route from vrouter"
  pn_vrouter_static:
    pn_action: remove
    pn_vrouter: ansible-vrouter
    pn_network: 192.168.11.2
    pn_netmask: 255.255.255.0
    pn_gateway: 10.9.9.1
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter static
  route command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter
  static route command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the
  target.
  returned: always
  type: bool
"""


VROUTER_EXISTS = None
ROUTE_EXISTS = None

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
    This method checks if vRouter exists on the target node.
    This method also checks for idempotency using the show command.
    If the given vRouter exists, return VROUTER_EXISTS as True else False.
    If an OSPF network with the given ip exists on the given vRouter,
    return NETWORK_EXISTS as True else False.

    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VROUTER_EXISTS
    """
    vrouter = module.params['pn_vrouter']
    network = module.params['pn_network']
    gateway = module.params['pn_gateway']
    show_cli = pn_cli(module)
    # Global flags
    global VROUTER_EXISTS, ROUTE_EXISTS

    cliswitch = module.params['pn_cliswitch']
    if cliswitch:
        show_cli = show_cli.replace('switch', '')
        show_cli = show_cli.replace(cliswitch, '')

    # Check for vRouter
    check_vrouter = show_cli + ' vrouter-show format name no-show-headers '
    check_vrouter = shlex.split(check_vrouter)
    out = module.run_command(check_vrouter)[1]
    out = out.split()

    VROUTER_EXISTS = True if vrouter in out else False
    
    # Check for static route
    check_route = show_cli + ' vrouter-static-route-show vrouter-name %s ' % vrouter
    check_route += ' format network,gateway-ip no-show-headers'
    check_route = shlex.split(check_route)
    out = module.run_command(check_route)[1]

    if network in out and gateway in out:
        ROUTE_EXISTS = True
    else:
        ROUTE_EXISTS = False


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
            msg="vRouter Static route %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vRouter Static route %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vRouter Static route %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove']),
            pn_vrouter=dict(required=True, type='str'),
            pn_network=dict(required=True, type='str'),
            pn_netmask=dict(required=True, type='str'),
            pn_gateway=dict(type='str'),
            pn_bfd_dst=dict(type='str'),
            pn_distance=dict(type='str')
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vrouter-static-route-' + action
    vrouter = module.params['pn_vrouter']
    network = module.params['pn_network']
    netmask = module.params['pn_netmask']
    gateway = module.params['pn_gateway']
    bfd_dst = module.params['pn_bfd_dst']
    distance = module.params['pn_distance']

    # Building the CLI command string
    cli = pn_cli(module)
    check_cli(module)

    cli += ' %s vrouter-name %s network %s ' % (command, vrouter, network)
    cli += ' netmask ' + netmask

    if gateway:
        cli += ' gateway-ip ' + gateway

    if action == 'add':
        if VROUTER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter %s does not exist' % vrouter
            )
        if ROUTE_EXISTS is True:
            module.exit_json(
                skipped=True,
                msg='Route with network %s and gateway %s already exists'
                    % (network, gateway)
            )

        if bfd_dst:
            cli += ' bfd-dst-ip ' + bfd_dst

        if distance:
            cli += ' distance ' + distance

    if action == 'remove':
        if VROUTER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter %s does not exist' % vrouter
            )
        if ROUTE_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='Route with network %s and gateway %s does not exist'
                    % (network, gateway)
            )

    run_cli(module, cli)

if __name__ == '__main__':
    main()
