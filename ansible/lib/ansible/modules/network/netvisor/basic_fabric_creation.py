#!/usr/bin/python
""" PN Basic Fabric Creation """

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

import shlex
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import *

DOCUMENTATION = """
---
module: basic_fabric_creation
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to perform fabric creation/join.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention.
    It performs following steps:
        - Disable STP
        - Enable all ports
        - Create/Join fabric
        - Enable STP
options:
    pn_switch_list:
      description:
        - Specify list of switches.
      required: False
      type: list
    pn_fabric_name:
      description:
        - Specify name of the fabric.
      required: False
      type: str
    pn_inband_ip:
      description:
        - Inband ips to be assigned to switches starting with this value.
      required: False
      default: 172.16.0.0/24.
      type: str
    pn_switch:
      description:
        - Name of the switch on which this task is currently getting executed.
      required: False
      type: str
    pn_toggle_port_speed:
      description:
        - Flag to indicate if port speed should be toggled for better topology visibility.
      required: False
      default: True
      type: bool
    pn_autotrunk:
      description:
        - Flag to enable/disable auto-trunk setting.
      required: False
      choices: ['enable', 'disable']
      type: str
    pn_autoneg:
      description:
        - Flag to enable/disable auto-neg for T2+ platforms.
      required: False
      type: bool
"""

EXAMPLES = """
- name: Fabric creation/join
    basic_fabric_creation:
      pn_cliusername: "{{ ansible_user }}"
      pn_clipassword: "{{ ansible_ssh_pass }}"
      pn_switch: "{{ inventory_hostname }}"
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


def modify_stp(module, modify_flag, task, msg):
    """
    Method to enable/disable STP (Spanning Tree Protocol) on a switch.
    :param module: The Ansible module to fetch input parameters.
    :param modify_flag: Enable/disable flag to set.
    """
    cli = pn_cli(module)
    cli += ' switch-local stp-show format enable '
    current_state = run_command(module, cli, task, msg).split()[1]

    state = 'yes' if modify_flag == 'enable' else 'no'

    if current_state == state:
        cli = pn_cli(module)
        cli += ' switch-local stp-modify %s ' % modify_flag
        run_command(module, cli, task, msg)


def create_fabric(module, fabric_name, task, msg):
    """
    Create a fabric
    :param module: The Ansible module to fetch input parameters.
    :param fabric_name: Name of the fabric to create.
    :return: 'Created fabric fabric_name'
    """
    cli = pn_cli(module)
    cli += ' fabric-create name %s fabric-network mgmt ' % fabric_name
    run_command(module, cli, task, msg)
    cli = pn_cli(module)
    cli += ' admin-service-modify web if mgmt '
    run_command(module, cli, task, msg)
    CHANGED_FLAG.append(True)
    return 'Created fabric {}'.format(fabric_name)


def join_fabric(module, fabric_name, task, msg):
    """
    Join existing fabric
    :param module: The Ansible module to fetch input parameters.
    :param fabric_name: Name of the fabric to join to.
    :return: 'Joined fabric fabric_name'
    """
    cli = pn_cli(module)
    cli += ' fabric-join name %s ' % fabric_name
    run_command(module, cli, task, msg)
    CHANGED_FLAG.append(True)
    return 'Joined fabric {}'.format(fabric_name)


def is_switches_connected(module, task, msg):
    """
    Check if switches are physically connected to each other.
    :param module: The Ansible module to fetch input parameters.
    :return: True if connected else False.
    """
    cli = pn_cli(module)
    cli += ' lldp-show format switch,sys-name parsable-delim , '
    sys_names = run_command(module, cli, task, msg)

    if sys_names is not None:
        switch1 = module.params['pn_switch_list'][0]
        switch2 = module.params['pn_switch_list'][1]

        sys_names = list(set(sys_names.split()))
        for cluster in sys_names:
            if switch1 in cluster and switch2 in cluster:
                return True

    return False


def configure_fabric(module, switch_list, switch, fabric_name, task, msg):
    """
    Create/join fabric.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing if fabric got created/joined/already configured.
    """
    cli = pn_cli(module)
    cli += ' fabric-info format name no-show-headers '
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Above fabric-info cli command will throw an error, if switch is not part
    # of any fabric. So if err, we need to create/join the fabric.
    if err:
        if len(switch_list) == 2:
            if not is_switches_connected(module, task, msg):
                msg = 'Error: Switches are not connected to each other'
                results = {
                    'switch': switch,
                    'output': msg
                }
                module.exit_json(
                    unreachable=False,
                    failed=True,
                    exception=msg,
                    summary=results,
                    task='Fabric creation',
                    msg='Fabric creation failed',
                    changed=False
                )

            new_fabric = False
            cli = pn_cli(module)
            cli += ' fabric-show format name no-show-headers '
            existing_fabrics = run_command(module, cli, task, msg)

            if existing_fabrics is not None:
                existing_fabrics = existing_fabrics.split()
                if fabric_name not in existing_fabrics:
                    new_fabric = True

            if new_fabric or existing_fabrics is None:
                output = create_fabric(module, fabric_name, task, msg)
            else:
                output = join_fabric(module, fabric_name, task, msg)
        else:
            output = create_fabric(module, fabric_name, task, msg)
    else:
        return 'Fabric already configured'

    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(argument_spec=dict(
        pn_switch_list=dict(required=False, type='list', default=[]),
        pn_fabric_name=dict(required=True, type='str'),
        pn_inband_ip=dict(required=False, type='str', default='172.16.0.0/24'),
        pn_switch=dict(required=False, type='str'),
        pn_toggle_port_speed=dict(required=False, type='bool', default=True),
        pn_dns_ip=dict(required=False, type='str', default=''),
        pn_dns_secondary_ip=dict(required=False, type='str', default=''),
        pn_domain_name=dict(required=False, type='str', default=''),
        pn_ntp_server=dict(required=False, type='str', default=''),
        pn_autotrunk=dict(required=False, type='str',
                          choices=['enable', 'disable'], default='disable'),
        pn_autoneg=dict(required=False, type='bool', default=False), )
    )

    global CHANGED_FLAG
    global task
    global msg

    task = 'Fabric creation'
    msg = 'Fabric setup failed'

    results = []
    fabric_name = module.params['pn_fabric_name']
    autoneg = module.params['pn_autoneg']
    autotrunk = module.params['pn_autotrunk']
    switch_list = module.params['pn_switch_list']
    current_switch = module.params['pn_switch']
    inband_ipv4 = module.params['pn_inband_ip']
    dns_ip = module.params['pn_dns_ip']
    dns_secondary_ip = module.params['pn_dns_secondary_ip']
    domain_name = module.params['pn_domain_name']
    ntp_server = module.params['pn_ntp_server']

    # Create/join fabric
    out = configure_fabric(module, switch_list, current_switch, fabric_name, task, msg)
    results.append({
        'switch': current_switch,
        'output': out
    })

    # Determine 'msg' field of JSON that will be returned at the end
    msg = out if 'already configured' in out else 'Fabric creation succeeded'

    # Find internal ports
    internal_ports = find_internal_ports(module, current_switch, task, msg)

    # Modify auto-neg for T2+ platforms
    if autoneg is True:
        out = modify_auto_neg(module, current_switch, switches=switch_list)
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': out
        })

    # Configure fabric control network to mgmt
    configure_control_network(module, 'mgmt', task, msg)
    CHANGED_FLAG.append(True)
    results.append({
        'switch': current_switch,
        'output': u"Configured fabric control network to mgmt"
    })

    # Enable/disable auto-trunk
    modify_auto_trunk(module, autotrunk, task, msg)
    results.append({
        'switch': current_switch,
        'output': u"Auto-trunk {}d".format(autotrunk)
    })

    # Make switch setup static
    make_switch_setup_static(module, dns_ip, dns_secondary_ip, domain_name, ntp_server, task, msg)
    CHANGED_FLAG.append(True)
    results.append({
        'switch': current_switch,
        'output': 'Switch setup successful'
    })

    if 'Success' in ports_modify_jumbo(module, 'jumbo', internal_ports, task, msg):
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': 'Jumbo enabled in ports'
        })

    # Disable STP
    modify_stp(module, 'disable', task, msg)

    # Enable ports
    if 'Success' in enable_ports(module, internal_ports,task, msg):
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': 'Ports enabled'
        })

    # Convert port speeds for better topology visibility
    if module.params['pn_toggle_port_speed']:
        out = toggle_ports(module, current_switch, internal_ports, task, msg)
        results.append({
            'switch': current_switch,
            'output': out
        })

    # Assign in-band ips.
    out, CHANGED_FLAG = assign_inband_ipv4(module, switch_list, current_switch, inband_ipv4, CHANGED_FLAG, task, msg)
    if out:
        results.append({
            'switch': current_switch,
            'output': out
        })

    # Enable STP
    modify_stp(module, 'enable', task, msg)

    # Exit the module and return the required JSON
    module.exit_json(
        unreachable=False,
        msg=msg,
        summary=results,
        exception='',
        task='Fabric creation',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()
