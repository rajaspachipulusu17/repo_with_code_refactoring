#!/usr/bin/python
""" PN ZTP vRouter Setup """

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import *


DOCUMENTATION = """
---
module: pn_ztp_vrouter_setup
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
  pn_ztp_vrouter_setup:
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


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_loopback_ip=dict(required=False, type='str', default='109.109.109.1/32'),
            pn_vrrp_id=dict(required=False, type='str', default='18'),
            pn_current_switch=dict(required=False, type='str'),
            pn_spine_list=dict(required=False, type='list', default=[]),
            pn_leaf_list=dict(required=False, type='list', default=[]),
            pn_pim_ssm=dict(required=False, type='bool', default=False),
            pn_ospf_redistribute=dict(required=False, type='str',
                                      choices=['none', 'static', 'connected',
                                               'rip', 'bgp'],
                                      default='none'),
            pn_bgp_redistribute=dict(required=False, type='str',
                                     choices=['none', 'static', 'connected',
                                              'rip', 'ospf'],
                                     default='none'),
            pn_bgp_as=dict(required=False, type='str'),
            pn_loopback_ip_v6=dict(required=False, type='str'),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Vrouter creation'
    msg = 'Vrouter creation failed'

    results = []
    message = ''
    loopback_address = module.params['pn_loopback_ip']
    current_switch = module.params['pn_current_switch']
    vrrp_id = module.params['pn_vrrp_id']
    ospf_redistribute = module.params['pn_ospf_redistribute']
    pim_ssm = module.params['pn_pim_ssm']
    bgp_redistribute = module.params['pn_bgp_redistribute']
    bgp_as = module.params['pn_bgp_as']

    # Create vrouters
    change_flag = list()
    change_flag, output = create_vrouter(module, current_switch, change_flag, task, msg,
                                         vrrp_id, ospf_redistribute, pim_ssm, bgp_redistribute, bgp_as)
    message += output
    if True in change_flag:
        CHANGED_FLAG.append(True)

    # Assign loopback ip to vrouters
    output = ''
    change_flag = list()
    change_flag, output = assign_loopback_and_router_id(module, loopback_address, current_switch,
                                                        change_flag, task, msg)
    if output:
        message += output
    if True in change_flag:
        CHANGED_FLAG.append(True)

    replace_string = current_switch + ': '
    for line in message.splitlines():
        if replace_string in line:
            results.append({
                'switch': current_switch,
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
