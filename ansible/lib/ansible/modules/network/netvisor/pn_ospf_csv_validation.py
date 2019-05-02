#!/usr/bin/python
""" PN OSPF CSV Validation """

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

import socket
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: pn_ospf_csv_validation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to validate ospf configuration csv file.
    Csv file format: switch_name, local_port, interface_ip(with subnet), area_id
    Csv file should not be empty. This module validates the given csv file.
options:
    pn_ospf_data:
      description: String containing ospf config data parsed from csv file.
      required: True
      type: str
    pn_switch_list:
      description: Specify list of all switches.
      required: True
      type: list
"""

EXAMPLES = """
- name: Validate ospf csv file
  pn_ospf_csv_validation:
    pn_ospf_data: "{{ lookup('file', '{{ csv_file }}') }}"
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
            pn_ospf_data=dict(required=True, type='str'),
            pn_switch_list=dict(required=True, type='list'),
        )
    )

    output = ''
    line_count = 0
    existing_interface_ip = []

    ospf_data = module.params['pn_ospf_data'].splitlines()
    if ospf_data:
        ospf_data_list = [i.strip() for i in ospf_data]

        for row in ospf_data_list:
            row = row.strip()
            line_count += 1

            if not row.strip() or row.startswith('#'):
                # Skip blank lines and comments which starts with '#'
                continue
            else:
                elements = [x.strip() for x in row.split(',')]
                if len(elements) == 4:
                    switch_name = elements[0]
                    local_port = elements[1]
                    interface_ip = elements[2]
                    area_id = elements[3]

                    if (not switch_name or not local_port or not interface_ip or
                            not area_id):
                        output += 'Invalid entry at line number {}\n'.format(
                            line_count
                        )
                    else:
                        # Local switch name validation
                        if (re.match("^[a-zA-Z0-9_.:-]+$", switch_name) is
                                None or switch_name not in
                                module.params['pn_switch_list']):
                            output += 'Invalid local switch name {} '.format(
                                switch_name)
                            output += 'at line number {}\n'.format(line_count)

                        # Local port number validation
                        if (not local_port.isdigit() or
                                int(local_port) not in range(1, 256)):
                            output += 'Invalid port {} '.format(local_port)
                            output += 'at line number {}\n'.format(
                                line_count)

                        # INTERFACE IP address validation
                        try:
                            if '/' not in interface_ip:
                                raise socket.error
                            else:
                                address_with_subnet = interface_ip.split('/')
                                address = address_with_subnet[0]
                                subnet = address_with_subnet[1]
                                dot_count = address.count('.')
                                if dot_count != 3 or address in existing_interface_ip:
                                    raise socket.error

                                socket.inet_aton(address)
                                if (not subnet.isdigit() or
                                        int(subnet) not in range(1, 33)):
                                    raise socket.error

                                existing_interface_ip.append(address)
                        except socket.error:
                            output += 'Invalid interface ip {} '.format(interface_ip)
                            output += 'at line number {}. '.format(line_count)
                            output += 'Note: Format of interface_ip -> x.x.x.x/subnet\n'

                        # AREA-ID validation
                        if (not area_id.isdigit() or
                                int(area_id) not in range(0, 42949672)):
                            output += 'Invalid area-id {} '.format(area_id)
                            output += 'at line number {}\n'.format(
                                line_count)
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
        task='Validate ospf csv file'
    )

if __name__ == '__main__':
    main()
