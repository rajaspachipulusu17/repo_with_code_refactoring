#!/usr/bin/python
""" PN VRRP CSV Validation """

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

import re
import socket

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: pn_vrrp_csv_validation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to validate vrrp configuration csv file.
Csv file format: vlan id, gateway ip, primary ip, secondary ip, active_switch.
Csv file should not be empty. This module validates the given csv file.
options:
    pn_csv_data:
      description: String containing trunk config data parsed from csv file.
      required: True
      type: str
    pn_switch_list:
      description: Specify list of all switches.
      required: True
      type: list
"""

EXAMPLES = """
- name: Validate vrrp csv file
  pn_vrrp_csv_validation:
    pn_csv_data: "{{ lookup('file', '{{ vrrp_file }}') }}"
    pn_switch_list: "{{ groups['switch'] }}"
"""

RETURN = """
msg:
  description: It contains output of each validation.
  returned: always
  type: str
changed:
  description: Indicates whether the validation caused changes on the target.
  returned: always
  type: bool
unreachable:
  description: Empty string.
  returned: always
  type: bool
failed:
  description: Indicates if csv validation failed or not.
  returned: always
  type: bool
exception:
  description: Empty string.
  returned: always
  type: str
task:
  description: Name of the task getting executed.
  returned: always
  type: str
summary:
  description: Indicates whether csv file is valid or invalid.
  returned: always
  type: str
"""


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_csv_data=dict(required=True, type='str'),
            pn_switch_list=dict(required=True, type='list'),
        )
    )

    output = ''
    line_count = 0
    valid_vlans = []
    existing_ip = []

    csv_data = module.params['pn_csv_data'].splitlines()
    if csv_data:
        csv_data_list = [i.strip() for i in csv_data]
        for row in csv_data_list:
            row = row.strip()
            line_count += 1

            if not row.strip() or row.startswith('#'):
                # Skip blank lines and comments which starts with '#'
                continue
            else:
                elements = [x.strip() for x in row.split(',')]
                if len(elements) == 5:
                    vlan = elements.pop(0)
                    gateway_ip = elements.pop(0)
                    primary_ip = elements.pop(0)
                    secondary_ip = elements.pop(0)
                    switch = elements.pop(0)

                    if (not vlan or not gateway_ip or not primary_ip or
                            not secondary_ip or not switch):
                        output += 'Invalid entry at line number {}\n'.format(
                            line_count
                        )
                    else:
                        # Vlan ID validation
                        if vlan in valid_vlans:
                            output += 'Duplicate vlan {} '.format(vlan)
                            output += 'at line number {}\n'.format(line_count)

                        if (not vlan.isdigit() or
                                int(vlan) not in range(2, 4093)):
                            output += 'Invalid vlan {} '.format(vlan)
                            output += 'at line number {}\n'.format(line_count)
                        else:
                            valid_vlans.append(vlan)

                        # IP address validation
                        for ip in [gateway_ip, primary_ip, secondary_ip]:
                            try:
                                if '/' not in ip:
                                    raise socket.error
                                else:
                                    address_with_subnet = ip.split('/')
                                    address = address_with_subnet[0]
                                    subnet = address_with_subnet[1]
                                    dot_count = address.count('.')
                                    if dot_count != 3 or address in existing_ip:
                                        raise socket.error

                                    socket.inet_aton(address)
                                    if (not subnet.isdigit() or
                                            int(subnet) not in range(1, 33)):
                                        raise socket.error

                                    existing_ip.append(address)
                            except socket.error:
                                output += 'Invalid ip {} '.format(ip)
                                output += 'at line number {}\n'.format(
                                    line_count)

                        # Switch name validation
                        if (re.match("^[a-zA-Z0-9_.:-]+$", switch) is None or
                                switch not in module.params['pn_switch_list']):
                            output += 'Invalid switch name {} '.format(switch)
                            output += 'at line number {}\n'.format(line_count)

                else:
                    output += 'Invalid entry at line number {}\n'.format(
                        line_count)
    else:
        output += 'Csv file should not be empty\n'

    if not output:
        msg = 'Valid csv file'
        failed_flag = False
    else:
        msg = 'Invalid csv file'
        failed_flag = True

    module.exit_json(
        unreachable=False,
        msg=output,
        summary=msg,
        exception='',
        failed=failed_flag,
        changed=False,
        task='Validate vrrp csv file'
    )

if __name__ == '__main__':
    main()
