#!/usr/bin/python
""" PN CLI ipv6security-raguard-port-add/remove """

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
module: pn_ipv6security_raguard_port
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove ipv6security-raguard-port.
description:
  - C(add): Add ports to RA Guard Policy
  - C(remove): Remove ports to RA Guard Policy
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - ipv6security-raguard-port configuration command.
    required: true
    choices: ['add', 'remove']
    type: str
  pn_name:
    description:
      - RA Guard Policy Name
    required: false
    type: str
  pn_ports:
    description:
      - Ports attached to RA Guard Policy
    required: false
    type: str
"""

EXAMPLES = """
- name: add ipv6 RA guard ports
  pn_ipv6security_raguard_port:
    pn_action: 'add'
    pn_name: 'test'
    pn_ports: '10'

- name: remove ipv6 RA guard ports
  pn_ipv6security_raguard_port:
    pn_action: 'remove'
    pn_name: 'test'
    pn_ports: '10'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the ipv6security-raguard-port command.
  returned: always
  type: list
stderr:
  description: set of error responses from the ipv6security-raguard-port command.
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
            msg="ipv6security-raguard-port %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="ipv6security-raguard-port %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="ipv6security-raguard-port %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove']),
            pn_name=dict(required=False, type='str'),
            pn_ports=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    name = module.params['pn_name']
    ports = module.params['pn_ports']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'ipv6security-raguard-port-' + action

    if name:
        cli += ' name ' + name
    if ports:
        cli += ' ports ' + ports
    
    run_cli(module, cli)

if __name__ == '__main__':
    main()
