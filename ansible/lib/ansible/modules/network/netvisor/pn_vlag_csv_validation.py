#!/usr/bin/python
""" PN VLAG CSV Validation """

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

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: pn_vlag_csv_validation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to validate vlag configuration csv file.
    Csv file format: vlag_name, local_switch, local_port, peer_switch, peer_port
    Csv file should not be empty. This module validates the given csv file.
options:
    pn_csv_data:
      description: String containing vlag config data parsed from csv file.
      required: True
      type: str
    pn_switch_list:
      description: Specify list of all switches.
      required: True
      type: list
"""

EXAMPLES = """
- name: Validate vlag csv file
  pn_vlag_csv_validation:
    pn_csv_data: "{{ lookup('file', '{{ csv_file }}') }}"
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

    csv_data = module.params['pn_csv_data'].splitlines()
    if csv_data:
        csv_data_list = [i.strip() for i in csv_data]
        for row in csv_data_list:
            line_count += 1

            if not row.strip() or row.startswith('#'):
                # Skip blank lines and comments which starts with '#'
                continue
            else:
                elements = [x.strip() for x in row.split(',')]
                if len(elements) == 5:
                    vlag_name = elements[0]
                    local_switch = elements[1]
                    local_port = elements[2]
                    peer_switch = elements[3]
                    peer_port = elements[4]

                    if (not vlag_name or not local_switch or not local_port or
                            not peer_switch or not peer_port):
                        output += 'Invalid entry at line number {}\n'.format(
                            line_count
                        )
                    else:
                        # vlag name validation
                        if re.match("^[a-zA-Z0-9_.:-]+$", vlag_name) is None:
                            output += 'Invalid vlag name {} '.format(vlag_name)
                            output += 'at line number {}\n'.format(line_count)

                        if len(vlag_name) > 59:
                            output += 'vlag name length cannot be greater '
                            output += 'than 59 characters '
                            output += 'at line number {}\n'.format(line_count)

                        # Local switch name validation
                        if (re.match("^[a-zA-Z0-9_.:-]+$", local_switch) is
                                None or local_switch not in
                                module.params['pn_switch_list']):
                            output += 'Invalid local switch name {} '.format(
                                local_switch)
                            output += 'at line number {}\n'.format(line_count)

                        # Local port name validation
                        if re.match("^[a-zA-Z0-9_.:-]+$", local_port) is None:
                            output += 'Invalid local port name {} '.format(
                                local_port)
                            output += 'at line number {}\n'.format(
                                line_count)

                        # Peer switch name validation
                        if (re.match("^[a-zA-Z0-9_.:-]+$", peer_switch) is
                                None or peer_switch not in
                                module.params['pn_switch_list']):
                            output += 'Invalid peer switch name {} '.format(
                                peer_switch)
                            output += 'at line number {}\n'.format(line_count)

                        # Peer port name validation
                        if re.match("^[a-zA-Z0-9_.:-]+$", peer_port) is None:
                            output += 'Invalid peer port name {} '.format(
                                peer_port)
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
        task='Validate vlag csv file'
    )

if __name__ == '__main__':
    main()

