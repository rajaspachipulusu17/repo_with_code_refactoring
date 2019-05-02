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
module: pn_vnet
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version_added: "2.8"
short_description: CLI command to create/modify/delete vnet.
description:
   - Execute vnet-create or vnet-modify or vnet-delete.

options:
   pn_cliswitch:
     description:
         - Target switch to run the CLI on.
     required: False
   state:
     description:
         - State the action to perform. Use 'present' to create vnet,
         'update' to modify vnet and 'absent' to delete vnet.
     required: True
   pn_name:
     description:
         - VNET name.
     required: True
     type: str
   pn_scope:
     description:
         - VNET scope - local or fabric.
     type: str
   pn_vrg:
     description:
         - Virtual Resource Group (VRG) assigned to VNET.
     type: str
   pn_vlan_type:
     description:
         - type of VLAN for this VNET.
     required: False
     choices: ['public', 'private']
     default: public
     type: str
   pn_num_vlans:
     description:
         - number of global VLANs assigned to VNET.
     required: False
     type: str
   pn_vlans:
     description:
         - VLANs assigned to public VLAN VNET.
     required: False
     type: str
   pn_public_vlans:
     description:
         - Public VLANs assigned to private VLAN VNET.
     required: False
     type: str
   pn_num_private_vlans:
     description:
         - number of private VLANs VNET is allowed to create.
     required: False
     type: str
   pn_vxlans:
     description:
         - VXLAN IDs assigned to VNET.
     required: False
     type: str
   pn_vxlan_end:
     description:
         - VXLAN IDs assigned to VNET.
     required: False
     type: str
   pn_managed_ports:
     description:
         - VNET exclusive ports.
     required: False
     type: str
   pn_shared_ports:
     description:
        - VNET shared ports.
     required: False
     type: str
   pn_shared_port_vlans:
     description:
         - VNET shared port vlans.
     required: False
     type: str
   pn_config_admin:
     description:
         - VNET admin configured.
     required: False
     type: bool
   pn_admin:
     description:
         - VNET admin name.
     required: False
     type: str
   pn_create_vnet_mgr:
     description:
         - create default vnet-manager service.
     required: False
     type: bool
   pn_vnet_mgr_name:
     description:
         - VNET manager name.
     required: False
     type: str
   pn_vnet_mgr_storage_pool:
     description:
         - VNET manager storage pool.
     required: False
     type: str
"""

EXAMPLES = """
- name: create VNET
  pn_vnet:
    state: 'present'
    pn_name: 'Sample-test-vnet'
    pn_scope: 'fabric'
    pn_vrg:
    pn_vlan_type: 'public'
    pn_num_vlans:
    pn_vlans:
    pn_public_vlans:
    pn_num_private_vlans:
    pn_vxlans:
    pn_vxlan_end:
    pn_managed_ports:
    pn_shared_ports:
    pn_shared_port_vlans:
    pn_config_admin:
    pn_admin:
    pn_create_vnet_mgr:
    pn_vnet_mgr_name:
    pn_vnet_mgr_storage_pool:

- name: modify VNET
  pn_vnet:
    state: 'update'
    pn_name: 'Sample-test-vnet'
    pn_vlans:
    pn_vxlans:
    pn_vxlan_end:
    pn_managed_ports:
    pn_num_private_vlans:
    pn_public_vlans:
    pn_shared_ports:
    pn_shared_port_vlans:

- name: Delete VNET
  pn_vnet:
    state: 'absent'
    pn_name: 'Sample-test-vnet'
"""

Return = """
command:
  description: the CLI command run on the target node.
  returned: always
  type: str
stdout:
  description: set of responses from the vnet command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vnet command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


def get_existing_vnets(module, cli):
    """"
    Method to obtain existing vnets.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The CLI string
    :return: list of existing vnets.
    """
    name = module.params['pn_name']
    cli += ' vnet-show name %s format name, no-show-headers ' % name
    existing_vnets = module.run_command(cli, use_unsafe_shell=True)[1]
    existing_vnets = existing_vnets.splitlines()
    if existing_vnets:
        return name


def main():
    """ This section is for arguments parsing """
    state_map = dict(
        present='vnet-create',
        absent='vnet-delete',
        update='vnet-modify'
    )

    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            state=dict(required=True, type='str',
                       choices=state_map.keys()),
            pn_name=dict(required=True, type='str'),
            pn_scope=dict(type='str',
                          choices=['fabric', 'local', 'cluster']),
            pn_vrg=dict(required=False, type='str'),
            pn_vlan_type=dict(required=False, type='str',
                              choices=['public', 'private']),
            pn_num_vlans=dict(required=False, type='str'),
            pn_vlans=dict(required=False, type='str'),
            pn_public_vlans=dict(required=False, type='str'),
            pn_num_private_vlans=dict(required=False, type='str'),
            pn_vxlans=dict(required=False, type='str'),
            pn_vxlan_end=dict(required=False, type='str'),
            pn_managed_ports=dict(required=False, type='str'),
            pn_shared_ports=dict(required=False, type='str'),
            pn_shared_port_vlans=dict(required=False, type='str'),
            pn_config_admin=dict(required=False, type='bool'),
            pn_admin=dict(required=False, type='str'),
            pn_create_vnet_mgr=dict(required=False, type='bool'),
            pn_vnet_mgr_name=dict(required=False, type='str'),
            pn_vnet_mgr_storage_pool=dict(required=False, type='str')
        ),
        required_if=(
                    ["state", "present", ["pn_name", "pn_scope"]],
                    ["state", "absent", ["pn_name"]],
                    ["state", "update", ["pn_name"]]
        )
    )

    # Accessing the arguments
    cliswitch = module.params['pn_cliswitch']
    state = module.params['state']
    name = module.params['pn_name']
    scope = module.params['pn_scope']
    vrg = module.params['pn_vrg']
    vlan_type = module.params['pn_vlan_type']
    num_vlans = module.params['pn_num_vlans']
    vlans = module.params['pn_vlans']
    public_vlans = module.params['pn_public_vlans']
    num_private_vlans = module.params['pn_num_private_vlans']
    vxlans = module.params['pn_vxlans']
    vxlan_end = module.params['pn_vxlan_end']
    managed_ports = module.params['pn_managed_ports']
    shared_ports = module.params['pn_shared_ports']
    shared_port_vlans = module.params['pn_shared_port_vlans']
    config_admin = module.params['pn_config_admin']
    admin = module.params['pn_admin']
    create_vnet_mgr = module.params['pn_create_vnet_mgr']
    vnet_mgr_name = module.params['pn_vnet_mgr_name']
    vnet_mgr_storage_pool = module.params['pn_vnet_mgr_storage_pool']

    command = state_map[state]

    cli = pn_cli(module, cliswitch)
    existing_vnet = get_existing_vnets(module, cli)

    if command == 'vnet-delete':
        if name != existing_vnet:
            module.exit_json(
                skipped=True,
                msg='vnet with name %s does not exist' % name
            )

        cli += ' %s name %s ' % (command, name)

    else:
        if command == 'vnet-create':
            if name == existing_vnet:
                module.exit_json(
                    skipped=True,
                    msg='vnet with name %s already exists' % name
                )

            cli += ' %s name %s scope %s ' % (command, name, scope)

            if vrg:
                cli += ' vrg ' + vrg

            if vlan_type:
                cli += ' vlan-type ' + vlan_type

            if num_vlans:
                cli += ' num-vlans ' + num_vlans

            cli += booleanArgs(config_admin, 'config-admin', 'no-config-admin')

            if admin:
                cli += ' admin ' + admin

            cli += booleanArgs(create_vnet_mgr, 'create-vnet-mgr', 'no-create-vnet-mgr')

            if vnet_mgr_name:
                cli += ' vnet-mgr-name ' + vnet_mgr_name

            if vnet_mgr_storage_pool:
                cli += ' vnet-mgr-storage-pool ' + vnet_mgr_storage_pool

        if command == 'vnet-modify':
            if name != existing_vnet:
                module.fail_json(
                    failed=True,
                    msg='vnet with name %s does not exist' % name
                )

            cli += ' %s name %s ' % (command, name)

        if vlans:
            cli += ' vlans ' + vlans

        if public_vlans:
            cli += ' public-vlans ' + public_vlans

        if num_private_vlans:
            cli += ' num-private-vlan ' + num_private_vlans

        if vxlans:
            cli += ' vxlans ' + vxlans

        if vxlan_end:
            cli += ' vxlan-end ' + vxlan_end

        if managed_ports:
            cli += ' managed-ports ' + managed_ports

        if shared_ports:
            cli += ' shared-ports ' + shared_ports

        if shared_port_vlans:
            cli += ' shared-port-vlans ' + shared_port_vlans

    run_cli(module, cli, state_map)


if __name__ == '__main__':
    main()
