#!/usr/bin/python
""" PN Trunk Creation """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, create_trunk


DOCUMENTATION = """
---
module: pn_trunk_creation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to create trunks.
Trunk csv file format: switch_name, trunk_name, list of ports.
options:
    pn_switch_list:
      description:
        - Specify list of all switches.
      required: False
      type: list
      default: []
    pn_trunk_data:
      description:
        - String containing trunk data parsed from csv file.
      required: False
      type: str
      default: ''
"""

EXAMPLES = """
- name: Create trunks
  pn_trunk_creation:
    pn_switch_list: "{{ groups['switch'] }}"
    pn_trunk_data: "{{ lookup('file', '{{ trunk_file }}') }}"
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
            pn_switch_list=dict(required=False, type='list', default=[]),
            pn_trunk_data=dict(required=False, type='str', default=''),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Create trunk',
    msg = 'Trunk creation failed'

    results = []
    message = ''
    switch_list = module.params['pn_switch_list']

    # Create trunk
    trunk_data = module.params['pn_trunk_data']
    trunk_data = trunk_data.strip()
    if trunk_data:
        trunk_data = trunk_data.splitlines()
        trunk_data_list = [i.strip() for i in trunk_data]
        for row in trunk_data_list:
            row = row.strip()
            if not row or row.startswith('#'):
                continue
            else:
                elements = [x.strip() for x in row.split(',')]
                switch_name = elements.pop(0)
                trunk_name = elements.pop(0)
                ports = ','.join(elements)

                if switch_name in switch_list:
                    CHANGED_FLAG, output = create_trunk(module, switch_name,
                                                        trunk_name, ports, CHANGED_FLAG, task, msg)
                    message += output
    else:
        CHANGED_FLAG.append(False)

    for switch in switch_list:
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
        msg='Trunk creation succeeded' if True in CHANGED_FLAG \
             else "No trunk configuration done",
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Create trunks'
    )

if __name__ == '__main__':
    main()

