#!/usr/bin/python
""" PN CLI fabric-local-modify """
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
module: pn_fabric_local
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify fabric-local.
description:
  - C(modify): modify fabric local information
options:
  pn_action:
    description:
      - fabric-local configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_fabric_network:
    description:
      - fabric administration network
    required: false
    choices: ['in-band', 'mgmt']
  pn_vlan:
    description:
      - VLAN assigned to fabric
    required: false
    type: str
  pn_control_network:
    description:
      - control plane network
    required: false
    choices: ['in-band', 'mgmt']
  pn_fabric_advertisement_network:
    description:
      - network to send fabric advertisements on
    required: false
    choices: ['inband-mgmt', 'inband-only']
"""

EXAMPLES = """
- name: Fabric local module
  pn_fabric_local:
    pn_current_switch: "{{ inventory_hostname }}"
    pn_action: "modify"
    pn_vlan: "610"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the fabric-local command.
  returned: always
  type: list
stderr:
  description: set of error responses from the fabric-local command.
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
            msg="%s: fabric-local %s operation failed" \
            % (module.params['pn_current_switch'], action),
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="%s: fabric-local %s operation completed"  \
            % (module.params['pn_current_switch'], action),
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="%s: fabric-local %s operation completed" \
                % (module.params['pn_current_switch'], action),
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_current_switch=dict(required=True, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_fabric_network=dict(required=False, type='str',
                                   choices=['mgmt', 'in-band']),
            pn_vlan=dict(required=False, type='str'),
            pn_control_network=dict(required=False, type='str',
                                    choices=['in-band', 'mgmt']),
            pn_fabric_advertisement_network=dict(required=False, type='str',
                                                 choices=['inband-mgmt',
                                                 'inband-only']),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    fabric_network = module.params['pn_fabric_network']
    vlan = module.params['pn_vlan']
    control_network = module.params['pn_control_network']
    fabric_adv_network = module.params['pn_fabric_advertisement_network']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += ' fabric-local-' + mod_action
    if mod_action in ['modify']:
        if fabric_network:
            cli += ' fabric-network ' + fabric_network
        if vlan:
            cli += ' vlan ' + vlan
        if control_network:
            cli += ' control-network ' + control_network
        if fabric_adv_network:
            cli += ' fabric-advertisement-network ' + fabric_adv_network
    run_cli(module, cli)

if __name__ == '__main__':
    main()
