#!/usr/bin/python
# Copyright: (c) 2018, Pluribus Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, run_cli, booleanArgs

DOCUMENTATION = """
---
module: pn_vnet_manager
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version_added: "2.8"
short_description: CLI command to create/modify/delete vnet-manager.
description:
   - Execute vnet-manager-create or vnet-manager-modify or
   vnet-manager-delete command.

options:
   pn_cliswitch:
     description:
         - Target switch to run the CLI on.
     required: False
   state:
     description:
         - State the action to perform. Use 'present' to create vnet-manager,
         'absent' to delete vnet-manager and 'update' to modify vnet-manager.
     required: True
   pn_name:
     description:
        - Name of the service config.
     type: str
   pn_vnet:
     description:
        - vnet assigned to service.
     type: str
   pn_enable:
     description:
        - state of service.
     required: False
     choices: ['enable','disable']
   pn_location:
     description:
        - location of service (fabric-node name).
     required: False
     type: str
   pn_storage-pool:
     description:
        - storage pool assigned to service.
     required: False
     type: str
   pn_gateway:
     description:
        - gateway IP address for service.
      required: False
      type: str
"""

EXAMPLES = """
- name: create a VNET-Manager
  pn_vnet_manager:
    state: 'present'
    pn_name: 'sample-vnet'
    pn_vnet: 'fabric-sample-global'
    pn_enable:
    pn_location:
    pn_storage-pool:

- name: modify a VNET-Manager
  pn_vnet_manager:
    state: 'update'
    pn_name: 'sample-vnet'
    pn_enable:
    pn_location:
    pn_storage-pool:
    pn_gateway:

- name: delete VNET-Manager
  pn_vnet_manager:
    state: 'absent'
    pn_name: 'sample-vnet'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
  returned: always
  type: str
stdout:
  description: set of responses from the vnet-manager command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vnet-manager command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

VNET_MANAGER_EXISTS = None


def check_cli(module, cliswitch):
    """This method checks for idempotency using vnet-manager-show command.
        If a user with the given name exists, return VNET_MANAGER_EXISTS as True else False.
        :param module: The Ansible module to fetch input parameters
        :param cliswitch: The switch name
        :return Global Booleans: VNET_MANAGER_EXISTS"""

    name = module.params['pn_name']
    cli = pn_cli(module, cliswitch)
    cli += ' vnet-manager-show format name no-show-headers'
    global VNET_MANAGER_EXISTS
    existing_vnet_manager = module.run_command(cli, use_unsafe_shell=True)[1]
    existing_vnet_manager = existing_vnet_manager.split()
    VNET_MANAGER_EXISTS = True if name in existing_vnet_manager else False


def main():
    """ This section is for arguments parsing """
    state_map = dict(
        present='vnet-manager-create',
        absent='vnet-manager-delete',
        update='vnet-manager-modify'
    )

    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            state=dict(required=True, type='str',
                       choices=state_map.keys()),
            pn_name=dict(required=True, type='str'),
            pn_vnet=dict(required=False, type='str'),
            pn_enable=dict(required=False, type='bool'),
            pn_location=dict(required=False, type='str'),
            pn_storage_pool=dict(required=False, type='str'),
            pn_gateway=dict(required=False, type='str')
        ),
        required_if=(
                    ["state", "present", ["pn_name", "pn_vnet"]],
                    ["state", "absent", ["pn_name"]],
                    ["state", "update", ["pn_name"]]
        )
    )

    # Accessing the arguments
    cliswitch = module.params['pn_cliswitch']
    state = module.params['state']
    name = module.params['pn_name']
    vnet = module.params['pn_vnet']
    enable = module.params['pn_enable']
    location = module.params['pn_location']
    storage_pool = module.params['pn_storage_pool']
    gateway = module.params['pn_gateway']

    check_cli(module, cliswitch)
    command = state_map[state]

    # Building the CLI command string
    cli = pn_cli(module, cliswitch)

    if command == 'vnet-manager-delete':
        if VNET_MANAGER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vnet-manager with name %s does not exit' % name
            )
        cli += '%s name %s' % (command, name)

    else:
        if command == 'vnet-manager-modify':
            if VNET_MANAGER_EXISTS is False:
                module.fail_json(
                    failed=True,
                    msg='vnet-manager with name %s does not exist' % name
                )

            cli += '%s name %s' % (command, name)

            if gateway:
                cli += ' gateway ' + gateway

        if command == 'vnet-manager-create':
            if VNET_MANAGER_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='Maximum number of vnet-manager reached'
                )

            cli += ' %s name %s vnet %s ' % (command, name, vnet)

        cli += booleanArgs(enable, 'enable', 'disable')

        if location:
            cli += ' location ' + location

        if storage_pool:
            cli += ' storage-pool ' + storage_pool

    run_cli(module, cli, state_map)


if __name__ == '__main__':
    main()
