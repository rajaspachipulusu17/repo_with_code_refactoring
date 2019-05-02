#!/usr/bin/python
""" PN CLI pn-ztp-ports-disable """

# Copyright 2018 Pluribus Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli


EXAMPLES = """
- name: port disable
  pn_ztp_ports_disable:
    pn_current_switch: "{{ inventory_hostname }}"
    pn_port_disable: True
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

def run_cli(module, cli):
    """
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    results = []
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    if out:
        return out
    if err:
        json_msg = {
            'switch': module.params['pn_current_switch'],
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception=err.strip(),
            summary=results,
            task='Port modify',
            msg='Port modify failed',
            changed=False
        )
    else:
        return 'Success'


def port_modify(module):
    """
    Method to disable the ports which doesnt belong to ztp fabric.
    :param module: The Ansible module to fetch input parameters.
    :return: switches with disabled ports
    """
    result = list()
    cli = pn_cli(module)
    clicopy = cli

    if module.params['pn_port_disable'] is True:
        cli += 'fabric-node-show format name parsable-delim ,'
        switch_list = list(set(run_cli(module, cli).strip().split()))

        cli = clicopy
        cli += 'lldp-show format switch,local-port,sys-name parsable-delim ,'
        lldp_list = run_cli(module, cli).strip().split('\n')
        for row in lldp_list:
            row = row.split(',')
            if row[2] in switch_list:
                continue
            else:
                cli = clicopy
                cli += 'switch %s port-config-modify ' % row[0]
                cli += 'port %s disable ' % row[1]
                run_cli(module, cli)
                CHANGED_FLAG.append(True)
                result.append({
                    'switch': row[0],
                    'output': 'Port %s connected to %s disabled' % (row[1], row[2])
                })
    return result


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_current_switch=dict(required=False, type='str'),
            pn_port_disable=dict(required=False, type='bool', default=True)
        )
    )

    results = []
    results = port_modify(module)

    module.exit_json(
        unreachable=False,
        msg='Ports modify succeeded',
        summary=results,
        exception='',
        task='Ports modify',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()
