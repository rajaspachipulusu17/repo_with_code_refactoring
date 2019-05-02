#!/usr/bin/python
""" PN Vlan Creation """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, run_command, create_vlan

DOCUMENTATION = """
---
module: pn_vlan_creation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to create vlans.
Vlan csv file format: vlan id, list of untagged ports.
options:
    pn_switch:
      description:
        - Name of the switch on which this task is currently getting executed.
      required: True
      type: str
    pn_vlan_data:
      description:
        - String containing vlan data parsed from csv file.
      required: False
      type: str
      default: ''
"""

EXAMPLES = """
- name: Create vlans
  pn_vlan_creation:
    pn_switch: "{{ inventory_hostname }}"
    pn_vlan_data: "{{ lookup('file', '{{ vlan_file }}') }}"
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
            pn_switch=dict(required=True, type='str'),
            pn_vlan_data=dict(required=False, type='str', default=''),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Create vlans'
    msg = 'vlan creation failed'
    results = []
    message = ''

    # Create vlans
    vlan_data = module.params['pn_vlan_data'].splitlines()
    if vlan_data:
        vlan_data_list = [i.strip() for i in vlan_data]
        for row in vlan_data_list:
            if not row.strip() or row.startswith('#'):
                continue
            else:
                elements = [x.strip() for x in row.split(',')]
                elements = filter(None, elements)
                switch_name = elements.pop(0)
                vlan_id = elements.pop(0)
                if len(elements) > 0:
                    untagged_ports = ','.join(elements)
                else:
                    untagged_ports = None

                output, CHANGED_FLAG = create_vlan(module, vlan_id, switch_name, CHANGED_FLAG, task, msg, untagged_ports)
                message += output
    else:
        CHANGED_FLAG.append(False)

    for line in message.splitlines():
        if line:
            switch = module.params['pn_switch']
            if ':' in line:
                line = line.split(':')
                switch = line[0]
                line = line[1]

            results.append({
                'switch': switch,
                'output': line
            })

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        msg='vlan creation succeeded' if True in CHANGED_FLAG else "No Vlan Configuration Done",
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Create vlans'
    )


if __name__ == '__main__':
    main()
