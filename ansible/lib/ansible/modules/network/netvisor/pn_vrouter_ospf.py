#!/usr/bin/python
""" PN-CLI vrouter-ospf-add/remove """
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
module: pn_vrouter_ospf
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove ospf protocol to a vRouter.
description:
  - Execute vrouter-ospf-add, vrouter-ospf-remove command.
  - This command adds/removes Open Shortest Path First(OSPF) routing
    protocol to a virtual router(vRouter) service.
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
      - vRouter OSPF config command.
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
  pn_ospf_area:
    description:
    - Stub area number for the configuration. Required for vrouter-ospf-add.
    type: str
"""

EXAMPLES = """
- name: "Add OSPF to vrouter"
  pn_vrouter_ospf:
    pn_action: add
    pn_vrouter: ansible-vrouter
    pn_network: 192.168.11.2
    pn_netmask: 255.255.255.0
    pn_ospf_area: 0

- name: "Remove OSPF from vrouter"
  pn_vrouter_ospf:
    pn_action: remove
    pn_vrouter: ansible-vrouter
    pn_network: 192.168.11.2
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter ospf
  config command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter
  ospf config command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the
  target.
  returned: always
  type: bool
"""


VROUTER_EXISTS = None
NETWORK_EXISTS = None


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
    :return Global Booleans: VROUTER_EXISTS, NETWORK_EXISTS
    """
    vrouter = module.params['pn_vrouter']
    network = module.params['pn_network']
    show_cli = pn_cli(module)
    # Global flags
    global VROUTER_EXISTS, NETWORK_EXISTS

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

    # Check for OSPF networks
    check_network = show_cli + ' vrouter-ospf-show vrouter-name %s ' % vrouter
    check_network += 'format network no-show-headers'
    check_network = shlex.split(check_network)
    out = module.run_command(check_network)[1]

    NETWORK_EXISTS = True if network in out else False


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
            msg="vRouter OSPF %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vRouter OSPF %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vRouter OSPF %s operation completed" % action,
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
            pn_ospf_area=dict(type='str')
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vrouter-ospf-' + action
    vrouter = module.params['pn_vrouter']
    network = module.params['pn_network']
    netmask = module.params['pn_netmask']
    ospf_area = module.params['pn_ospf_area']

    # Building the CLI command string
    cli = pn_cli(module)
    check_cli(module)

    if action == 'add':
        if VROUTER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter %s does not exist' % vrouter
            )
        if NETWORK_EXISTS is True:
            module.exit_json(
                skipped=True,
                msg='OSPF with network ip %s already exists on %s'
                    % (network, vrouter)
            )
        cli += ' %s vrouter-name %s network %s ' % (command, vrouter, network)

        if netmask:
            cli += ' netmask ' + netmask

        if ospf_area:
            cli += ' ospf-area ' + ospf_area

    if action == 'remove':
        if VROUTER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter %s does not exist' % vrouter
            )
        if NETWORK_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='OSPF with network ip %s does not exist on %s'
                    % (network, vrouter)
            )
        cli += ' %s vrouter-name %s network %s ' % (command, vrouter, network)

    run_cli(module, cli)

if __name__ == '__main__':
    main()
