#!/usr/bin/python
""" PN CLI vlag-create/vlag-delete/vlag-modify """
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
module: pn_vlag
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2.0
short_description: CLI command to create/delete/modify vlag.
description:
  - Execute vlag-create, vlag-delete or vlag-modify command.
options:
  pn_cliswitch:
    description:
      - Target switch to run this command on.
    type: str
  pn_action:
    description:
      - The vLAG configuration command.
    required: true
    choices: ['create', 'delete', 'modify']
    type: str
  pn_name:
    description:
      - Name for the vLAG.
    required: true
    type: str
  pn_port:
    description:
      - Local VLAG port.
    type: str
  pn_peer_port:
    description:
      - VLAG peer port.
    type: str
  pn_mode:
    description:
      - VLAG mode.
    choices: ['active-active', 'active-standby']
    type: str
  pn_peer_switch:
    description:
      - Name of the peer switch.
    type: str
  pn_failover_action:
    description:
      - failover-move-l2 sends gratious ARPs or not.
    choices: ['move', 'ignore']
    type: str
  pn_lacp_mode:
    description:
      - Specify the LACP mode.
    choices: ['off', 'passive', 'active']
    type: str
  pn_lacp_timeout:
    description:
      - Specify the LACP timeout as slow or fast.
    type: str
  pn_lacp_fallback:
    description:
      - Specify the LACP fallback mode as bundled or individual.
    choices: ['bundle', 'individual']
    type: str
  pn_lacp_fallback_timeout:
    description:
      - Specify the LACP fallback timeout between 30 and 60 seconds,
        default 50 seconds.
    type: str
  pn_lacp_port_priority:
    description:
      - Specify the LACP port priority.
    type: str
"""

EXAMPLES = """
- name: create a VLAG
  pn_vlag:
    pn_action: 'create'
    pn_name: spine-to-leaf
    pn_port: 'spine01-to-leaf'
    pn_peer_port: 'spine02-to-leaf'
    pn_peer_switch: spine02
    pn_mode: 'active-active'

- name: delete VLAGs
  pn_vlag:
    pn_action: 'delete'
    pn_name: spine-to-leaf
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: the set of responses from the vlag command.
  returned: always
  type: list
stderr:
  description: the set of error responses from the vlag command.
  returned: on error
  type: list
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

VLAG_EXISTS = None


def check_cli(module):
    """
    This method checks for idempotency using the vlag-show command.
    If a vlag with given vlag exists, return VLAG_EXISTS as True else False.
    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VLAG_EXISTS
    """
    name = module.params['pn_name']
    switch = module.params['pn_cliswitch']
    show_cli = pn_cli(module, switch)

    show_cli += ' vlag-show format name no-show-headers'
    show_cli = shlex.split(show_cli)
    # Global flags
    global VLAG_EXISTS

    out = module.run_command(show_cli)[1]

    out = out.split()

    VLAG_EXISTS = True if name in out else False


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
        module.exit_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="vLAG %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vLAG %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vLAG %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for argument parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_port=dict(type='str'),
            pn_peer_port=dict(type='str'),
            pn_mode=dict(type='str',
                         choices=['active-standby', 'active-active']),
            pn_peer_switch=dict(type='str'),
            pn_failover_action=dict(type='str',
                                    choices=['move', 'ignore']),
            pn_lacp_mode=dict(type='str',
                              choices=['off', 'passive', 'active']),
            pn_lacp_timeout=dict(type='str',
                                 choices=['slow', 'fast']),
            pn_lacp_fallback=dict(type='str',
                                  choices=['individual', 'bundled']),
            pn_lacp_fallback_timeout=dict(type='str'),
            pn_lacp_port_priority=dict(type='str')
        )
    )

    # Argument accessing
    switch = module.params['pn_cliswitch']
    action = module.params['pn_action']
    command = ' vlag-' + action
    name = module.params['pn_name']
    port = module.params['pn_port']
    peer_port = module.params['pn_peer_port']
    mode = module.params['pn_mode']
    peer_switch = module.params['pn_peer_switch']
    failover_action = module.params['pn_failover_action']
    lacp_mode = module.params['pn_lacp_mode']
    lacp_timeout = module.params['pn_lacp_timeout']
    lacp_fallback = module.params['pn_lacp_fallback']
    lacp_fallback_timeout = module.params['pn_lacp_fallback_timeout']
    lacp_port_priority = module.params['pn_lacp_port_priority']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    check_cli(module)
    cli += ' %s name %s ' % (command, name)

    if action == 'delete':
        if VLAG_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='VLAG with name %s does not exist' % name
            )

    else:
        if action == 'create':
            if VLAG_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='VLAG with name %s already exists' % name
                )

            cli += ' port %s peer-port %s ' % (port, peer_port)

            if mode:
                cli += ' mode ' + mode
            if peer_switch:
                cli += ' peer-switch ' + peer_switch

        if action == 'modify':
            if VLAG_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='VLAG with name %s does not exist' % name
                )

        if failover_action:
            cli += ' failover-' + failover_action + '-L2 '

        if lacp_mode:
            cli += ' lacp-mode ' + lacp_mode

        if lacp_timeout:
            cli += ' lacp-timeout ' + lacp_timeout

        if lacp_fallback:
            cli += ' lacp-fallback ' + lacp_fallback

        if lacp_fallback_timeout:
            cli += ' lacp-fallback-timeout ' + lacp_fallback_timeout

        if lacp_port_priority:
            cli += ' lacp-port-priority ' + lacp_port_priority

    run_cli(module, cli)

if __name__ == '__main__':
    main()
