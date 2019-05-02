#!/usr/bin/python
""" PN CLI vflow-system-modify """
#
# Copyright 2018 Pluribus Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli

DOCUMENTATION = """
---
module: pn_vflow_system
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify system vflows.
description:
  - C(modify): Modify the precedence of a system flow.
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - vtep configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_name:
    description:
      - Name for the vFlow.
    required: false
    type: str
  pn_enable:
    description:
      - Enable or disable flows in hardware.
    required: false
    type: bool
  pn_precedence:
    description:
      - Traffic priority value between 2 and 15.
    required: false
    type: str
  pn_flow_class:
    description:
      - vFlow class name.
    required: false
    type: str
"""

EXAMPLES = """
- name: Modify system vFlow
  pn_vflow_system:
    pn_action: 'modify'
    pn_name: 'System-A'
    pn_enable: True
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vflow-system command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vflow-system command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


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
            msg="vflow-system %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vflow-system %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vflow-system %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['modify']),
            pn_name=dict(required=True, type='str'),
            pn_enable=dict(required=True, type='bool'),
            pn_precedence=dict(required=False, type='str'),
            pn_flow_class=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    action = module.params['pn_action']
    name = module.params['pn_name']
    enable = module.params['pn_enable']
    precedence = module.params['pn_precedence']
    flow_class = module.params['pn_flow_class']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += 'vflow-system-' + action
    cli += ' name ' + name

    if action == 'modify':
        if enable is True:
            cli += ' enable '
        if enable is False:
            cli += ' no-enable '
        if precedence:
            cli += ' precedence ' + precedence
        if flow_class:
            cli += ' flow-class ' + flow_class

    run_cli(module, cli)

if __name__ == '__main__':
    main()
