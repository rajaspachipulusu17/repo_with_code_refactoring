#!/usr/bin/python
""" PN Vrouter Creation """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, run_command

DOCUMENTATION = """
---
module: pn_vrouter_creation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to create vrouters.
options:
    pn_switch_list:
      description:
        - Specify list of all switches.
      required: False
      type: list
      default: []
    pn_vrrp_id:
      description:
        - Specify the vrrp id to be assigned.
      required: False
      type: str
    pn_loopback_ip:
      description:
        - Specify loopback ip to be assigned to vrouters.
      required: False
      type: str
"""

EXAMPLES = """
- name: Create Vrouters
  pn_vrouter_creation:
    pn_switch_list: "{{ groups['switch'] }}"
    pn_vrrp_id: '18'
"""

RETURN = """
summary:
  description: It contains output of each configuration along with switch name.
  returned: always
  type: str
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
unreachable:
  description: Indicates whether switch was unreachable to connect.
  returned: always
  type: bool
failed:
  description: Indicates whether or not the execution failed on the target.
  returned: always
  type: bool
exception:
  description: Describes error/exception occurred while executing CLI command.
  returned: always
  type: str
task:
  description: Name of the task getting executed on switch.
  returned: always
  type: str
msg:
  description: Indicates whether configuration made was successful or failed.
  returned: always
  type: str
"""

CHANGED_FLAG = []


def create_vrouter(module, CHANGED_FLAG, task, msg):
    """
    Create a hardware vrouter.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing if vrouter got created or not.
    """
    output = ''
    vrrp_id = module.params['pn_vrrp_id']

    cli = pn_cli(module)
    cli += ' fabric-node-show format fab-name no-show-headers '
    fabric_name = list(set(run_command(module, cli, task, msg).split()))[0]
    vnet_name = fabric_name + '-global'

    cli = pn_cli(module)
    cli += ' vrouter-show format name no-show-headers '
    existing_vrouter_names = run_command(module, cli, task, msg)

    if existing_vrouter_names is not None:
        existing_vrouter_names = existing_vrouter_names.split()

    for switch in module.params['pn_switch_list']:
        new_vrouter = False
        vrouter_name = switch + '-vrouter'

        if (existing_vrouter_names is not None and vrouter_name not in
                existing_vrouter_names):
            new_vrouter = True

        if new_vrouter or existing_vrouter_names is None:
            cli = pn_cli(module)
            cli += ' switch %s ' % switch
            cli += ' vrouter-create name %s vnet %s ' % (vrouter_name,
                                                         vnet_name)
            if vrrp_id:
                cli += ' hw-vrrp-id %s ' % vrrp_id

            cli += ' enable router-type hardware '
            run_command(module, cli, task, msg)
            CHANGED_FLAG.append(True)
            output += '%s: Created vrouter with name %s\n' % (switch,
                                                              vrouter_name)

    return output, CHANGED_FLAG


def assign_loopback_and_router_id(module, loopback_address, CHANGED_FLAG, task, msg):
    """
    Add loopback interface and router id to vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param loopback_address: The loopback ip to be assigned.
    :return: String describing if loopback ip/router id got assigned or not.
    """
    output = ''

    address = loopback_address.split('.')
    static_part = str(address[0]) + '.' + str(address[1]) + '.'
    static_part += str(address[2]) + '.'
    vrouter_count = int(address[3])

    for switch in module.params['pn_switch_list']:
        add_loopback = False
        vrouter = switch + '-vrouter'
        ip = static_part + str(vrouter_count)

        # Add router id
        cli = pn_cli(module)
        cli += ' vrouter-modify name %s router-id %s ' % (vrouter, ip)
        run_command(module, cli, task, msg)
        output += '%s: Added router id %s to %s\n' % (switch, ip, vrouter)

        # Check existing loopback ip
        cli = pn_cli(module)
        cli += ' vrouter-loopback-interface-show ip %s ' % ip
        cli += ' format switch no-show-headers '
        existing_vrouter = run_command(module, cli, task, msg)

        if existing_vrouter is not None:
            existing_vrouter = existing_vrouter.split()
            if vrouter not in existing_vrouter:
                add_loopback = True

        # Add loopback ip if not already exists
        if add_loopback or existing_vrouter is None:
            cli = pn_cli(module)
            cli += ' vrouter-loopback-interface-add '
            cli += ' vrouter-name %s ip %s ' % (vrouter, ip)
            run_command(module, cli, task, msg)
            CHANGED_FLAG.append(True)
            output += '%s: Added loopback ip %s to %s\n' % (switch, ip, vrouter)

        vrouter_count += 1

    return output, CHANGED_FLAG


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_loopback_ip=dict(required=False, type='str', default=''),
            pn_vrrp_id=dict(required=False, type='str', default=''),
            pn_switch_list=dict(required=False, type='list', default=[]),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Create vRouter',
    msg = 'vRouter creation failed'

    results = []
    message = ''
    loopback_address = module.params['pn_loopback_ip']

    # Create vrouters
    message, CHANGED_FLAG = create_vrouter(module, CHANGED_FLAG, task, msg)

    # Assign loopback ip to vrouters
    if loopback_address:
        output, CHANGED_FLAG = assign_loopback_and_router_id(module, loopback_address,
                                                             CHANGED_FLAG, task, msg)
        message += output

    for switch in module.params['pn_switch_list']:
        replace_string = switch + ': '
        for line in message.splitlines():
            if replace_string in line:
                results.append({
                    'switch': switch,
                    'output': (line.replace(replace_string, '')).strip()
                })

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        msg='Vrouter creation succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Create vrouter'
    )


if __name__ == '__main__':
    main()
