#!/usr/bin/python
""" PN CLI vlan-port-add/vlan-port-remove """
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
module: pn_vlan_port
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
version: 2.0
short_description: CLI command to add/remove tagged/untagged ports to VLANs.
description:
  - Execute vlan-port-add or vlan-port-remove command.
options:
  pn_cliswitch:
    description:
      - Target switch(es) to run the cli on.
    required: False
    type: str
  pn_action:
    description:
      - The VLAN port action to perform on the switches.
    required: True
    choices: ['add', 'remove']
    type: str
  pn_vlanid:
    description:
      - Specify the VLAN ID.
    type: str
  pn_vlan_range:
    description:
      - Specify a range of VLAN IDs.
    type: str
  pn_vlan_vnet:
    description:
      - VNET for this VLAN.
    type: str
  pn_ports:
    description:
      - Specify the list of ports.
    type: str
  pn_tag_untag:
    description:
      - Specify either tagged or untagged.
    choices: ['tagged', 'untagged']
    type: str
"""

EXAMPLES = """
- name: Add tagged ports
  pn_vlan_port:
    pn_action: 'add'
    pn_vlanid: 1054
    pn_ports: '10,11,12'
    pn_tag_untag: tagged

- name: Add untagged ports to a range of vlans
  pn_vlan_port:
    pn_action: 'add'
    pn_vlanid: '100-105'
    pn_ports: '20,21,31,32'
    pn_tag_untag: untagged

- name: Remove ports from a vlan
  pn_vlan_port:
    pn_action: 'remove'
    pn_vlanid: 100
    pn_ports: '20, 21'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vlan port command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vlan port command.
  returned: on error
  type: list
changed:
  description: Indicates whether the module applied any configurations on the
  target.
  returned: always
  type: bool
"""


def run_cli(module, cli):
    """
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    action = module.params['pn_action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="vLAN port %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vLAN port %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vLAN port %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove']),
            pn_vlanid=dict(type='str'),
            pn_vlan_range=dict(type='str'),
            pn_vlan_vnet=dict(type='str'),
            pn_ports=dict(type='str'),
            pn_tag_untag=dict(type='str',
                              choices=['tagged', 'untagged'])
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    action = module.params['pn_action']
    command = 'vlan-port-' + action
    vlanid = module.params['pn_vlanid']
    vlan_range = module.params['pn_vlan_range']
    ports = module.params['pn_ports']
    vlan_vnet = module.params['pn_vlan_vnet']
    tag_untag = module.params['pn_tag_untag']

    cli = pn_cli(module, switch)
    cli += ' ' + command

    if vlanid:
        cli += ' vlan-id ' + vlanid
    if vlan_range:
        cli += ' vlan-range ' + vlan_range
    if ports:
        cli += ' ports ' + ports
    if vlan_vnet:
        cli += ' vlan-vnet ' + vlan_vnet

    if action == 'add':
        if tag_untag:
            cli += ' ' + tag_untag

    run_cli(module, cli)

if __name__ == '__main__':
    main()
