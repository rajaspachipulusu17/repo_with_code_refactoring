#!/usr/bin/python
# Copyright: (c) 2018, Pluribus Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: pn_prefix_list
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version_added: "2.8"
short_description: CLI command to create/delete prefix-list
description:
  - This module can be used to create and delete prefix list.
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  state:
    description:
      - State the action to perform. Use 'present' to create prefix-list and
        'absent' to delete prefix-list.
    required: True
    choices: [ "present", "absent"]
  pn_name:
    description:
      - Prefix List Name.
    required: false
    type: str
  pn_scope:
    description:
      - 'scope. Available valid values - local or fabric.'
    required: false
    choices: ['local', 'fabric']
"""

EXAMPLES = """
- name: Create prefix list
  pn_prefix_list:
    pn_cliswitch: "sw01"
    pn_name: "foo"
    pn_scope: "local"
    state: "present"

- name: Delete prefix list
  pn_prefix_list:
    pn_cliswitch: "sw01"
    pn_name: "foo"
    pn_scope: "local"
    state: "absent"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
  returned: always
  type: string
stdout:
  description: set of responses from the prefix-list command.
  returned: always
  type: list
stderr:
  description: set of error responses from the prefix-list command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, run_cli


def check_cli(module, cli):
    """
    This method checks for idempotency using the prefix-list-show command.
    If a name exists, return NAME_EXISTS
    :param module: The Ansible module to fetch input parameters
    :param cli: The CLI string
    :return Global Booleans: NAME_EXISTS
    """
    # Global flags
    global NAME_EXISTS
    name = module.params['pn_name']

    show = cli + \
        ' prefix-list-show format name no-show-headers'
    show = shlex.split(show)
    out = module.run_command(show)[1]

    out = out.split()

    NAME_EXISTS = True if name in out else False


def main():
    """ This section is for arguments parsing """

    global state_map
    state_map = dict(
        present='prefix-list-create',
        absent='prefix-list-delete'
    )

    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            state=dict(required=True, type='str',
                       choices=state_map.keys()),
            pn_name=dict(required=False, type='str'),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
        ),
        required_if=(
            ["state", "present", ["pn_name", "pn_scope"]],
            ["state", "absent", ["pn_name"]],
        ),
    )

    # Accessing the arguments
    cliswitch = module.params['pn_cliswitch']
    state = module.params['state']
    name = module.params['pn_name']
    scope = module.params['pn_scope']

    command = state_map[state]

    # Building the CLI command string
    cli = pn_cli(module, cliswitch)

    check_cli(module, cli)
    cli += ' %s name %s ' % (command, name)

    if command == 'prefix-list-delete':
        if NAME_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='prefix-list with name %s does not exist' % name
            )
    else:
        if command == 'prefix-list-create':
            if NAME_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='prefix list with name %s already exists' % name
                )
        cli += ' scope %s ' % scope

    run_cli(module, cli, state_map)


if __name__ == '__main__':
    main()
