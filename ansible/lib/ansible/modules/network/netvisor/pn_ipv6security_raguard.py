#!/usr/bin/python
""" PN CLI ipv6security-raguard-create/modify/delete """

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
module: pn_ipv6security_raguard
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete ipv6security-raguard.
description:
  - C(create): Add ipv6 RA Guard Policy
  - C(modify): Update ipv6 RA guard Policy
  - C(delete): Remove ipv6 RA Guard Policy
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - ipv6security-raguard configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_device:
    description:
      - RA Guard Device: host or router
    required: false
    choices: ['host', 'router']
  pn_access_list:
    description:
      - RA Guard Access List of Source IPs
    required: false
    type: str
  pn_prefix_list:
    description:
      - RA Guard Prefix List
    required: false
    type: str
  pn_router_priority:
    description:
      - RA Guard Router Priority
    required: false
    choices: ['low', 'medium', 'high']
  pn_name:
    description:
      - RA Guard Policy Name
    required: false
    type: str
"""

EXAMPLES = """
- name: create ipv6 security RA guard
  pn_ipv6security_raguard:
    pn_action: 'create'
    pn_name: 'test'
    pn_device: 'router'
    pn_access_list: 'block_ra'
    pn_prefix_list: 'block_prefix'

- name: delete ipv6 security RA guard
  pn_ipv6security_raguard:
    pn_action: 'delete'
    pn_name: 'test'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the ipv6security-raguard command.
  returned: always
  type: list
stderr:
  description: set of error responses from the ipv6security-raguard command.
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
            msg="ipv6security-raguard %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="ipv6security-raguard %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="ipv6security-raguard %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'modify', 'delete']),
            pn_device=dict(required=False, type='str',
                           choices=['host', 'router']),
            pn_access_list=dict(required=False, type='str'),
            pn_prefix_list=dict(required=False, type='str'),
            pn_router_priority=dict(required=False, type='str',
                                    choices=['low', 'medium', 'high']),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    device = module.params['pn_device']
    access_list = module.params['pn_access_list']
    prefix_list = module.params['pn_prefix_list']
    router_priority = module.params['pn_router_priority']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'ipv6security-raguard-' + action
    cli += ' name ' + name

    if action in ['create', 'modify']:
        if device:
            cli += ' device ' + device
        if access_list:
            cli += ' access-list ' + access_list
        if prefix_list:
            cli += ' prefix-list ' + prefix_list
        if router_priority:
            cli += ' router-priority ' + router_priority

    run_cli(module, cli)

if __name__ == '__main__':
    main()
