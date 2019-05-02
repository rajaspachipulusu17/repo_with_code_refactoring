i#!/usr/bin/python
""" PN CLI vrf-create/modify/delete """

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

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli

DOCUMENTATION = """
---
module: pn_vrf
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete vrf.
description:
  - C(create): create vrf
  - C(modify): modify vrf
  - C(delete): delete vrf
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - vrf configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_scope:
    description:
      - scope of the vrf
    required: false
    choices: ['local', 'cluster', 'fabric']
  pn_vrf_gw2:
    description:
      - gateway IP address 2
    required: false
    type: str
  pn_vrf_gw:
    description:
      - gateway IP address
    required: false
    type: str
  pn_vnet:
    description:
      - VNET for the VRF
    required: false
    type: str
  pn_name:
    description:
      - vrf name
    required: false
    type: str
"""

EXAMPLES = """
- name: create vrf
  pn_vrf:
    pn_action: 'create'
    pn_name: 'vrf-1'
    pn_vrf_gw: '10.10.1.1'
    pn_vrf_gw2: '20.20.1.1'

- name: delete vrf
  pn_vrf:
    pn_action: 'delete'
    pn_name: 'vrf-1'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrf command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrf command.
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
            msg="VRF %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="VRF %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="VRF %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                        choices=['create', 'modify', 'delete']),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'cluster', 'fabric']),
            pn_vrf_gw2=dict(required=False, type='str'),
            pn_vrf_gw=dict(required=False, type='str'),
            pn_vnet=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    scope = module.params['pn_scope']
    vrf_gw2 = module.params['pn_vrf_gw2']
    vrf_gw = module.params['pn_vrf_gw']
    vnet = module.params['pn_vnet']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'vrf-' + action
    cli += ' name ' + name

    if vnet:
        cli += ' vnet ' + vnet

    if action == 'create':
        if scope:
            cli += ' scope ' + scope

    if action in ['create', 'modify']:
        if vrf_gw2:
            cli += ' vrf-gw2 ' + vrf_gw2
        if vrf_gw:
            cli += ' vrf-gw ' + vrf_gw

    run_cli(module, cli)

if __name__ == '__main__':
    main()
