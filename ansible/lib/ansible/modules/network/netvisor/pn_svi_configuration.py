#!/usr/bin/python
""" PN SVI Configuration """

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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli, run_command

DOCUMENTATION = """
---
module: pn_svi_configuration
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to configure SVI.
svi csv file format: gateway_ip, vlan_id
options:
    pn_switch:
      description:
        - Name of the switch on which this task is currently getting executed.
      required: True
      type: str
    pn_svi_data:
      description:
        - String containing SVI data parsed from csv file.
      required: False
      type: str
      default: ''
"""

EXAMPLES = """
- name: Configure SVI
  pn_svi_configuration:
    pn_switch: "{{ inventory_hostname }}"
    pn_svi_data: "{{ lookup('file', '{{ svi_file }}') }}"
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


def svi_configuration(module, ip_gateway, switch, vlan_id, CHANGED_FLAG, task, msg):
    """
    Method to configure SVI inerface in the switch..
    :param module: The Ansible module to fetch input parameters.
    :param ip_gateway: IP address for the default gateway
    :param switch: Name of switch.
    :param vlan_id: The vlan id to be assigned.
    :return: String describing whether interface got added or not.
    """
    cli = pn_cli(module)
    clicopy = cli

    cli = clicopy
    cli += ' vrouter-show location %s format name' % switch
    cli += ' no-show-headers'
    vrouter_name = run_command(module, cli, task, msg).split()[0]

    cli = clicopy
    cli += ' vrouter-interface-show ip %s vlan %s ' % (ip_gateway, vlan_id)
    cli += ' format switch no-show-headers '
    existing_vrouter = run_command(module, cli, task, msg).split()
    existing_vrouter = list(set(existing_vrouter))

    if vrouter_name not in existing_vrouter:
        cli = clicopy
        cli += 'switch ' + switch
        cli += ' vrouter-interface-add vrouter-name ' + vrouter_name
        cli += ' vlan ' + vlan_id
        cli += ' ip ' + ip_gateway
        run_command(module, cli, task, msg)
        CHANGED_FLAG.append(True)
        return CHANGED_FLAG, 'Added vrouter interface with ip %s\n' % (ip_gateway)
    else:
        return CHANGED_FLAG, ''


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_switch=dict(required=True, type='str'),
            pn_svi_data=dict(required=False, type='str', default=''),
        )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Configure SVI'
    msg = 'SVI configuration failed'
    results = []
    message = ''
    switch = module.params['pn_switch']

    svi_data = module.params['pn_svi_data'].splitlines()
    if svi_data:
        svi_data_list = [i.strip() for i in svi_data]
        for row in svi_data_list:
            row = row.strip()
            if not row.strip() or row.startswith('#'):
                continue
            else:
                elements = row.split(',')
                ip_gateway = elements.pop(0).strip()
                vlan_id = elements.pop(0).strip()

                CHANGED_FLAG, output = svi_configuration(module, ip_gateway, switch, vlan_id,
                                                         CHANGED_FLAG, task, msg)
                message += output

    for line in message.splitlines():
        if line:
            results.append({
                'switch': module.params['pn_switch'],
                'output': line
            })

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        msg='SVI configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure SVI'
    )

if __name__ == '__main__':
    main()
