#!/usr/bin/python
""" PN CLI switch-route-create/modify/delete """

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
module: pn_switch_route
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete switch-route.
description:
  - C(create): create a switch route
  - C(modify): modify a switch route
  - C(delete): delete a switch route
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - switch-route configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_metric:
    description:
      - metric
    required: false
    type: str
  pn_nic:
    description:
      - NIC
    required: false
    type: str
  pn_netmask:
    description:
      - destination IP netmask
    required: false
    type: str
  pn_network:
    description:
      - destination IP address
    required: false
    type: str
  pn_gateway_ip:
    description:
      - gateway IP address
    required: false
    type: str
"""

EXAMPLES = """

"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the switch-route command.
  returned: always
  type: list
stderr:
  description: set of error responses from the switch-route command.
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
            msg="switch-route %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="switch-route %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="switch-route %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['create', 'modify', 'delete']),
            pn_metric=dict(required=False, type='str'),
            pn_nic=dict(required=False, type='str'),
            pn_netmask=dict(required=False, type='str'),
            pn_network=dict(required=False, type='str'),
            pn_gateway_ip=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    cliswitch = module.params['pn_cliswitch']
    action = module.params['pn_action']
    metric = module.params['pn_metric']
    nic = module.params['pn_nic']
    netmask = module.params['pn_netmask']
    network = module.params['pn_network']
    gateway_ip = module.params['pn_gateway_ip']

    # Building the CLI command string
    cli = pn_cli(module, cliswitch)
    cli += 'switch-route-' + action
    if action in ['create', 'modify']:
        if metric:
            cli += ' metric ' + metric

    if action in ['create', 'delete', 'modify']:
        if nic:
            cli += ' nic ' + nic
        if netmask:
            cli += ' netmask ' + netmask
        if network:
            cli += ' network ' + network
        if gateway_ip:
            cli += ' gateway-ip ' + gateway_ip

    run_cli(module, cli)

if __name__ == '__main__':
    main()

