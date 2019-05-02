#!/usr/bin/python
""" PN CLI vrouter-packet-relay-add/remove """

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
module: pn_vrouter_packet_relay
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove vrouter-packet-relay.
description:
  - C(add): add packet relay configuration for DHCP on vrouter
  - C(remove): remove packet relay configuration for DHCP on vrouter
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - vrouter-packet-relay configuration command.
    required: true
    choices: ['add', 'remove']
    type: str
  pn_forward_ip:
    description:
      - forwarding IP address
    required: false
    type: str
  pn_nic:
    description:
      - NIC
    required: false
    type: str
  pn_forward_proto:
    description:
      - protocol type to forward packets
    required: false
    type: str
  pn_vrouter_name:
    description:
      - name of service config
    required: false
    type: str
"""

EXAMPLES = """
- name: add vrouter packet relay
  pn_vrouter_packet_relay:
    pn_action: 'add'
    pn_vrouter_name: 'spine-vrouter'
    pn_forward_ip: '172.16.1.1'
    pn_forward_proto: 'dhcp'
    pn_nic: 'eth0'

- name: remove vrouter packet relay
  pn_vrouter_packet_relay:
    pn_action: 'remove'
    pn_vrouter_name: 'spine-vrouter'
    pn_forward_ip: '172.16.1.1'
    pn_forward_proto: 'dhcp'
    pn_nic: 'eth0'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter-packet-relay command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter-packet-relay command.
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
            msg="vrouter-packet-relay %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vrouter-packet-relay %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vrouter-packet-relay %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove']),
            pn_forward_ip=dict(required=False, type='str'),
            pn_nic=dict(required=False, type='str'),
            pn_forward_proto=dict(required=False, type='str'),
            pn_vrouter_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    forward_ip = module.params['pn_forward_ip']
    nic = module.params['pn_nic']
    forward_proto = module.params['pn_forward_proto']
    vrouter_name = module.params['pn_vrouter_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'vrouter-packet-relay-' + action

    if forward_ip:
        cli += ' forward-ip ' + forward_ip
    if nic:
        cli += ' nic ' + nic
    if forward_proto:
        cli += ' forward-proto ' + forward_proto
    if vrouter_name:
        cli += ' vrouter-name ' + vrouter_name
    
    run_cli(module, cli)

if __name__ == '__main__':
    main()
