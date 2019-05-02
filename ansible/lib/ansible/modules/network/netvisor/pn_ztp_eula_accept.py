#!/usr/bin/python
""" PN EULA Accept """
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
import threading

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: pn_ztp_eula_accept
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to accept EULA
options:
    pn_cliusername:
      description:
        - Provide login username if user is not root.
      required: True
      type: str
    pn_clipassword:
      description:
        - Provide login password if user is not root.
      required: True
      type: str
    pn_host_list:
      description:
        - Specify list of all hosts/switches.
      required: True
      type: list
    pn_host_ips:
      description:
        - Specify ips of all hosts/switches separated by comma.
      required: True
      type: str
"""

EXAMPLES = """
- name: Auto accept EULA
    pn_eula_accept:
      pn_cliusername: "{{ USERNAME }}"
      pn_clipassword: "{{ PASSWORD }}"
      pn_host_list: "{{ groups['all'] }}"
      pn_host_ips: "{{ groups['all'] |
        map('extract', hostvars, ['ansible_host']) | join(',') }}"

"""

RETURN = """
summary:
  description: It contains output along with switch name.
  returned: always
  type: str
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
unreachable:
  description: Indicates whether host was unreachable to connect.
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
result = []


def eula_accept(module, username, password, switch_name, ip):
    """
    Method to accept the eula.
    :param module: The Ansible module to fetch username and password.
    :param username: The cli username to be used.
    :param password: The new password to be input during eula-accept.
    :param switch_name: The switch name to be processed on.
    :param ip: The mgmt ip of the switch.
    """
    global result
    global CHANGED_FLAG
    global ssh_options
    ssh_options = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    cli = 'sshpass -p %s ' % password
    cli += 'ssh %s %s@%s ' % (ssh_options, username, ip)
    cli += 'eula-show'
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)
    if 'No license' in err or 'invalid license' in err:
        result.append({
            'switch': switch_name,
            'output': 'License not found',
            'status': 'fail'
        })
        CHANGED_FLAG.append(False)
    elif not out:
        cli = 'sshpass -p admin ssh %s ' % ssh_options
        cli += '%s@%s -- --quiet --script-password ' % (username, ip)
        cli += 'switch-setup-modify password %s ' % password
        cli += 'switch-name %s eula-accepted true' % switch_name
        cli = shlex.split(cli)
        module.run_command(cli)
        CHANGED_FLAG.append(True)
        result.append({
            'switch': switch_name,
            'output': 'Eula accepted',
            'status': 'pass'
        })
    else:
        result.append({
            'switch': switch_name,
            'output': 'Eula already accepted',
            'status': 'pass'
        })

def software_version_check(module, username, password, switch_name, ip):
    """
    Method to check switch version.
    :param module: The Ansible module to fetch username and password.
    :param username: The cli username to be used.
    :param password: The new password to be input during eula-accept.
    :param switch_name: The switch name to be processed on.
    :param ip: The mgmt ip of the switch.
    """
    ssh_options = "-q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    cli = 'sshpass -p %s ' % password
    cli += 'ssh %s %s@%s ' % (ssh_options, username, ip)
    cli += '-- --quiet software-show parsable-delim :'
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)
    out = out.strip()
    if out and len(out.split(":")) > 1:
        return out.split(":")[1]
    return None


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(argument_spec=dict(
        pn_cliusername=dict(required=True, type='str'),
        pn_clipassword=dict(required=True, type='str', no_log=True),
        pn_spine_list=dict(required=False, type='list', default=[]),
        pn_leaf_list=dict(required=False, type='list', default=[]),
        pn_spine_ips=dict(required=False, type='str', default=''),
        pn_leaf_ips=dict(required=False, type='str', default=''),
        pn_basic_switch_list=dict(required=False, type='list', default=[]),
        pn_basic_switch_ips=dict(required=False, type='str', default=''),
    ))

    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    spine_ips = module.params['pn_spine_ips']
    leaf_ips = module.params['pn_leaf_ips']
    basic_switch_list = module.params['pn_basic_switch_list']
    basic_switch_ips = module.params['pn_basic_switch_ips']
    switch_list = []
    switch_ips = []

    if basic_switch_list:
        switch_list += basic_switch_list
        if basic_switch_ips:
            switch_ips += basic_switch_ips.split(',')
    else:
        if spine_list:
            switch_list += spine_list
            if spine_ips:
                switch_ips += spine_ips.split(',')
        if leaf_list:
            switch_list += leaf_list
            if leaf_ips:
                switch_ips += leaf_ips.split(',')

    global result
    global msg_failure 
    msg_failure = "Eula accept failed." 
    count = 0
    threads = []

    for ip in switch_ips:
        threads.append(
            threading.Thread(
                target=eula_accept,
                args=(
                    module, username,
                    password, switch_list[count],
                    ip,
                )
            )
        )
        count += 1

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    count = 0
    sw_version = ''
    for ip in switch_ips:
        switch_sw_version = software_version_check(module, username, password, switch_list[count], ip)
        if not sw_version:
            sw_version = switch_sw_version
        elif switch_sw_version != sw_version:
            msg_failure += "One or more switches are not running the same version"
            out = '%s(%s) is different ' % (switch_list[count], switch_sw_version)
            out += 'from rest of the fabric (version:%s)\n' % sw_version
            result.append({
                'output': out,
                'status': 'fail'
            })
            break

        count += 1

    # Exit the module and return the required JSON
    if [1 for eula in result if eula['status'] == 'fail']:
        module.fail_json(
            unreachable=False,
            msg=msg_failure,
            summary=result,
            exception='',
            task='Accept eula',
            failed=False,
            changed=True if True in CHANGED_FLAG else False
        )
    else:
        module.exit_json(
            unreachable=False,
            msg='Eula accepted successfully',
            summary=result,
            exception='',
            task='Accept eula',
            failed=False,
            changed=True if True in CHANGED_FLAG else False
        )


if __name__ == '__main__':
    main()
