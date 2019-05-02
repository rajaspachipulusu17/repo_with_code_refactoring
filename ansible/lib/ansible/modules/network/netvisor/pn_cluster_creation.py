#!/usr/bin/python
""" PN Cluster Creation """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, create_cluster


DOCUMENTATION = """
---
module: pn_cluster_creation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to create cluster.
options:
    pn_switch_list:
      description:
        - Specify list of all switches.
      required: False
      type: list
      default: []
"""

EXAMPLES = """
- name: Create cluster
  pn_cluster_creation:
    pn_switch_list: "{{ groups['switch'] }}"
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
        )
    )

    results = []
    message = ''
    switch_list = module.params['pn_switch_list']

    global CHANGED_FLAG
    global task
    global msg

    task = 'Create cluster',
    msg = 'Cluster creation failed'

    # Create cluster
    if len(switch_list) == 2:
        node1 = switch_list[0]
        node2 = switch_list[1]
        name = node1 + '-' + node2 + '-cluster'
        mod = None
#        message += create_cluster(module, switch_list)
        message, output = create_cluster(module, node1, name, node1, node2, mod, CHANGED_FLAG, task, msg)

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
        msg='cluster creation succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Create clusters'
    )


if __name__ == '__main__':
    main()
