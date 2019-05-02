#!/usr/bin/python
""" PN Hosts File Validation """

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
module: pn_hosts_file_validation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to validate Ansible hosts/inventory file.
description:
    HOSTS file format: switch_name ansible_hosts=ip_address
    Every row in the hosts file should have above 2 elements.
    Hosts file should not be empty. This module validates the given hosts file.
options:
    pn_hosts_file_data:
      description: String containing Hosts file data parsed.
      required: True
      type: str
"""

EXAMPLES = """
- name: Validate hosts file
  pn_hosts_file_validation:
    pn_hosts_file_data: "{{ lookup('file', '{{ hosts_file }}') }}"
"""

RETURN = """
summary:
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
  description: Indicates if hosts file validation failed or not.
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
msg:
  description: Indicates whether hosts file is valid or invalid.
  returned: always
  type: str
"""


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_hosts_file_data=dict(required=True, type='str'),
        )
    )

    output = ''
    line_count = 0
    switch_names = []
    host_ips = []
    hosts_input = module.params['pn_hosts_file_data'].splitlines()

    if hosts_input:
        hosts_file_data = [i.strip() for i in hosts_input]

        # [spine] and [leaf] group validation
        if '[spine]' not in hosts_file_data and '[third_party_spine]' not in hosts_file_data:
            output += '[spine]/[third_party_spine] section is missing from the hosts file\n'

        if '[leaf]' not in hosts_file_data:
            output += '[leaf] section is missing from the hosts file\n'

        if not output:
            for row in hosts_file_data:
                line_count += 1
                row_copy = row
                if not row_copy.strip() or row.startswith('#'):
                    # Skip blank lines and comments which starts with '#'
                    continue
                else:
                    try:
                        elements = row.split()
                        if len(elements) == 1:
                            if '[spine]' in elements:
                                pass
                            elif '[leaf]' in elements:
                                pass
                            elif '[third_party_spine]' in elements:
                                pass
                            else:
                                raise IndexError

                        elif len(elements) == 2:
                            switch = elements[0]
                            if len(switch) > 59:
                                output += 'Switch name lenght should be less than 60, Invalid switch name {} '.format(
                                        switch)
                            ip = elements[1]

                            # Switch name validation
                            if switch not in switch_names:
                                switch_names.append(switch)
                                if (re.match("^[a-zA-Z0-9.-]+$", switch) is
                                        None):
                                    output += 'Invalid switch name {} '.format(
                                        switch)
                                    output += 'at line number {}\n'.format(
                                        line_count)
                            else:
                                output += 'Duplicate switch name {} '.format(
                                    switch)
                                output += 'at line number {}\n'.format(
                                    line_count)

                            # Host ip validation
                            ip_host = ip.split('=')
                            host = ip_host[0]
                            ip = ip_host[1]

                            if host != 'ansible_host':
                                raise IndexError

                            if ip not in host_ips:
                                host_ips.append(ip)
                                try:
                                    dot_count = ip.count('.')
                                    if dot_count != 3:
                                        raise socket.error

                                    socket.inet_aton(ip)
                                except socket.error:
                                    output += 'Invalid host ip {} '.format(ip)
                                    output += 'at line number {}\n'.format(
                                        line_count
                                    )
                            else:
                                output += 'Duplicate host ip {} '.format(ip)
                                output += 'at line number {}\n'.format(
                                    line_count)

                            # Ansible connection variable validation
                        else:
                            raise IndexError

                    except IndexError:
                        output += 'Invalid entry at line number {}\n'.format(
                            line_count
                        )
    else:
        output += 'Hosts file should not be empty\n'

    if not output:
        msg = 'Valid hosts file'
        failed_flag = False
    else:
        msg = 'Invalid hosts file'
        failed_flag = True

    module.exit_json(
        unreachable=False,
        msg=output,
        summary=msg,
        exception='',
        failed=failed_flag,
        changed=False,
        task='Validate hosts file'
    )

if __name__ == '__main__':
    main()

