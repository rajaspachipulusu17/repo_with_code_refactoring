#!/usr/bin/python
""" PN L3 VRRP CSV Validation """

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
module: pn_l3_vrrp_csv_validation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to validate L3 VRRP configuration csv file.
description:
    L3 VRRP config csv file format:
    VLAN, VRRP IP, Switch1 name, Switch2 name, VRRP ID, Active switch name
    Every row in the csv file should have at least first 3 elements.
    Every row cannot have more than above 6 elements.
    Csv file should not be empty. This module validates the given csv file.
options:
    pn_csv_data:
      description: String containing L3 VRRP data parsed from csv file.
      required: True
      type: str
    pn_leaf_list:
      description: Specify list of leaf switches.
      required: True
      type: list
"""

EXAMPLES = """
- name: Validate L3 VRRP csv file
  pn_l3_vrrp_csv_validation:
    pn_csv_data: "{{ lookup('file', '{{ csv_file }}') }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
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


def validate_switch_name(switch, leaf_list):
    """
    Method to validate switch name.
    :param switch: Name of the switch.
    :param leaf_list: List of leaf switches.
    :return: True if valid switch name else False.
    """
    # Switch name validation
    if (re.match("^[a-zA-Z0-9_.:-]+$", switch) is None or
            switch not in leaf_list):
        return False
    else:
        return True


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_csv_data=dict(required=True, type='str'),
            pn_leaf_list=dict(required=False, type='list'),
        )
    )

    output = ''
    line_count = 0
    leaf_list = module.params['pn_leaf_list']
    vlan_list = []
    existing_ip = []
    csv_data = module.params['pn_csv_data'].splitlines()
    switch_id_dict = {}

    if csv_data:
        csv_data_list = [i.strip() for i in csv_data]
        for row in csv_data_list:
            row = row.strip()
            line_count += 1

            if not row or row.startswith('#'):
                # Skip comments which starts with '#'
                continue
            else:
                elements = [x.strip() for x in row.split(',')]
                elements = filter(None, elements)
                # Check number of elements per row.
                if len(elements) != 3 and len(elements) != 6:
                    output += 'Invalid number of elements '
                    output += 'at line number {}.\n'.format(line_count)
                else:
                    vlan = elements[0]
                    ip = elements[1]
                    switch1 = elements[2]
                    clustered_leafs = []

                    if not ip or not vlan or not switch1:
                        output += 'Invalid entry at line number {}\n'.format(
                            line_count
                        )
                    else:
                        # VLAN ID validation
                        if (not vlan.isdigit() or vlan in vlan_list or
                                int(vlan) not in range(2, 4093)):
                            output += 'Invalid vlan id {} '.format(vlan)
                            output += 'at line number {}\n'.format(line_count)
                        else:
                            vlan_list.append(vlan)

                        # VRRP IP address validation
                        try:
                            if '/' not in ip:
                                raise socket.error
                            else:
                                address_with_subnet = ip.split('/')
                                address = address_with_subnet[0]
                                subnet = address_with_subnet[1]
                                dot_count = address.count('.')
                                addr = int(address.split('.')[3])
                                if dot_count != 3 or address in existing_ip:
                                    raise socket.error

                                if addr == 0 or addr >= 255:
                                    raise socket.error

                                socket.inet_aton(address)
                                if (not subnet.isdigit() or
                                        int(subnet) not in range(1, 33)):
                                    raise socket.error

                                existing_ip.append(address)
                        except socket.error:
                            output += 'Invalid vrrp ip {} '.format(ip)
                            output += 'at line number {}\n'.format(line_count)

                        # Switch1 name validation
                        if not validate_switch_name(switch1, leaf_list):
                            output += 'Invalid switch name {} '.format(switch1)
                            output += 'at line number {}\n'.format(line_count)
                        else:
                            clustered_leafs.append(switch1)

                    if len(elements) == 6:
                        switch2 = elements[3]
                        vrrp_id = elements[4]
                        active_switch = elements[5]

                        if not switch2 or not vrrp_id or not active_switch:
                            output += 'Invalid entry at '
                            output += 'line number {}\n'.format(
                                line_count
                            )
                        else:
                            # Switch2 name validation
                            if not validate_switch_name(switch2, leaf_list):
                                output += 'Invalid switch name {} '.format(
                                    switch2)
                                output += 'at line number {}\n'.format(
                                    line_count)
                            else:
                                clustered_leafs.append(switch2)
                                if tuple(clustered_leafs) not in switch_id_dict:
                                    switch_id_dict[
                                        tuple(clustered_leafs)] = None

                            # VRRP ID validation
                            if not vrrp_id.isdigit():
                                output += 'Invalid vrrp id {} '.format(vrrp_id)
                                output += 'at line number {}\n'.format(
                                    line_count)
                            else:
                                existing_vrrp_id = switch_id_dict.get(
                                    tuple(clustered_leafs))
                                if existing_vrrp_id is None:
                                    switch_id_dict[
                                        tuple(clustered_leafs)] = vrrp_id
                                else:
                                    if existing_vrrp_id != vrrp_id:
                                        output += 'Vrrp id cannot be '
                                        output += 'different at line '
                                        output += 'number {}\n'.format(
                                            line_count)

                            # Active switch name validation
                            if (not validate_switch_name(
                                    active_switch, leaf_list) or
                                    active_switch not in clustered_leafs):
                                output += 'Invalid switch name {} '.format(
                                    active_switch)
                                output += 'at line number {}\n'.format(
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
        task='Validate L3 vrrp csv file'
    )


if __name__ == '__main__':
    main()
