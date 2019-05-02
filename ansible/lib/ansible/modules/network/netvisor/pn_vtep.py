#!/usr/bin/python
""" PN CLI vtep-create/delete """

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
module: pn_vtep
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/delete vtep.
description:
  - C(create): create a vtep
  - C(delete): delete a vtep
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
    choices: ['create', 'delete']
    type: str
  pn_name:
    description:
      - vtep name
    required: false
    type: str
  pn_ip:
    description:
      - Primary IP address
    required: false
    type: str
  pn_vrouter_name:
    description:
      - name of the vrouter service
    required: false
    type: str
  pn_virtual_ip:
    description:
      - Virtual/Secondary IP address
    required: false
    type: str
  pn_location:
    description:
      - switch name
    required: false
    type: str
"""

EXAMPLES = """
- name: create vtep
  pn_vtep:
    pn_action: 'create'
    pn_name: 'vtep-1'
    pn_location: 'switch-1'
    pn_vrouter_name: 'switch1-vrouter'
    pn_ip: '10.20.11.2'
    pn_virtual_ip: '10.20.11.1'

- name: delete vtep
  pn_vtep:
    pn_action: 'delete'
    pn_name: 'vtep-1'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vtep command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vtep command.
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
            msg="VTEP %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="VTEP %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="VTEP %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete']),
            pn_name=dict(required=False, type='str'),
            pn_ip=dict(required=False, type='str'),
            pn_vrouter_name=dict(required=False, type='str'),
            pn_virtual_ip=dict(required=False, type='str'),
            pn_location=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    name = module.params['pn_name']
    ip = module.params['pn_ip']
    vrouter_name = module.params['pn_vrouter_name']
    virtual_ip = module.params['pn_virtual_ip']
    location = module.params['pn_location']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'vtep-' + action
    cli += ' name ' + name

    if action == 'create':
        if ip:
            cli += ' ip ' + ip
        if vrouter_name:
            cli += ' vrouter-name ' + vrouter_name
        if virtual_ip:
            cli += ' virtual-ip ' + virtual_ip
        if location:
            cli += ' location ' + location

    run_cli(module, cli)

if __name__ == '__main__':
    main()
