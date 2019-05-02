#!/usr/bin/python
""" PN Vlag Creation """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, create_vlag

DOCUMENTATION = """
---
module: pn_vlag_creation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to create vlags.
Vlag csv format: vlag_name, local_switch, local_port, peer_switch, peer_port.
options:
    pn_switch_list:
      description:
        - Specify list of all switches.
      required: False
      type: list
      default: []
    pn_vlag_data:
      description:
        - String containing vlag data parsed from csv file.
      required: False
      type: str
      default: ''
"""

EXAMPLES = """
- name: Create vlags
  pn_vlag_creation:
    pn_switch_list: "{{ groups['switch'] }}"
    pn_vlag_data: "{{ lookup('file', '{{ vlag_file }}') }}"
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
            pn_vlag_data=dict(required=False, type='str', default=''),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Create vLAG'
    msg = 'vLAG creation failed'

    results = []
    message = ''

    # Create vlag
    vlag_data = module.params['pn_vlag_data']
    vlag_data = vlag_data.strip()
    if vlag_data:
        vlag_data = vlag_data.splitlines()
        vlag_data_list = [i.strip() for i in vlag_data]
        for row in vlag_data_list:
            if not row or row.startswith('#'):
                continue
            else:
                elements = [item.strip() for item in row.split(',')]
                if len(elements) == 5:
                    vlag_name = elements[0]
                    local_switch = elements[1]
                    local_ports = elements[2]
                    peer_switch = elements[3]
                    peer_ports = elements[4]

                    CHANGED_FLAG, output = create_vlag(module, vlag_name, local_switch,
                                           local_ports, peer_switch, peer_ports,
                                            CHANGED_FLAG, task, msg)
                    message += output
    else:
        CHANGED_FLAG.append(False)

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
        msg='vlag creation succeeded' if True in CHANGED_FLAG else "No vlag configuration done",
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Create vlags'
    )


if __name__ == '__main__':
    main()
