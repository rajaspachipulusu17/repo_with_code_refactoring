#!/usr/bin/python
""" PN CLI cluster-create/cluster-delete """
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
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: pn_cluster
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2.0
short_description: CLI command to create/delete a cluster.
description:
  - Execute cluster-create or cluster-delete command.
options:
  pn_cliusername:
    description:
      - Provide login username if user is not root.
    required: False
    type: str
  pn_clipassword:
    description:
      - Provide login password if user is not root.
    required: False
    type: str
  pn_cliswitch:
    description:
      - Target switch to run the cli on.
    required: False
    type: str
  pn_action:
    description:
      - The Cluster configuration command.
    required: true
    choices: ['create', 'delete', 'modify']
    type: str
  pn_name:
    description:
      - Name of the cluster.
    required: true
    type: str
  pn_cluster_node1:
    description:
      - Name of the cluster node 1.
    type: str
  pn_cluster_node2:
    description:
      - Name of the cluster node 2.
    type: str
  pn_validate:
    description:
      - Validate the cluster link.
    type: bool
  pn_sync_timeout:
    description:
      - Cluster sync timeout between 500 and 20000.
    type: str
  pn_sync_offline_count:
    description:
      - Number of missed syncs after which cluster will go offline
        between 1 and 30.
    type: str
"""

EXAMPLES = """
- name: create spine cluster
  pn_cluster:
    pn_action: 'create'
    pn_name: 'spine-cluster'
    pn_cluster_node1: 'spine01'
    pn_cluster_node2: 'spine02'
    pn_validate: True

- name: delete spine cluster
  pn_cluster:
    pn_action: 'delete'
    pn_name: 'spine-cluster'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: the set of responses from the cluster command.
  returned: always
  type: list
stderr:
  description: the set of error responses from the cluster command.
  returned: on error
  type: list
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

NAME_EXISTS = None
NODE1_EXISTS = None
NODE2_EXISTS = None

def pn_cli(module):
    """
    This method is to generate the cli portion to launch the Netvisor cli.
    It parses the username, password, switch parameters from module.
    :param module: The Ansible module to fetch username, password and switch
    :return: returns the cli string for further processing
    """
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    cliswitch = module.params['pn_cliswitch']

    if username and password:
        cli = '/usr/bin/cli --quiet --user "%s":"%s" ' % (username, password)
    else:
        cli = '/usr/bin/cli --quiet '

    if cliswitch:
        cli += ' switch ' + cliswitch

    return cli


def check_cli(module):
    """
    This method checks for idempotency using the cluster-show command.
    If a cluster with given name exists, return NAME_EXISTS as True else False.
    If the given cluster-node-1 is already a part of another cluster, return
    NODE1_EXISTS as True else False.
    If the given cluster-node-2 is already a part of another cluster, return
    NODE2_EXISTS as True else False.
    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: NAME_EXISTS, NODE1_EXISTS, NODE2_EXISTS
    """
    name = module.params['pn_name']
    node1 = module.params['pn_cluster_node1']
    node2 = module.params['pn_cluster_node2']
    # Global flags
    global NAME_EXISTS, NODE1_EXISTS, NODE2_EXISTS

    show_cli = pn_cli(module)
    show_cli += ' cluster-show format name,cluster-node-1,cluster-node-2 '
    show_cli = shlex.split(show_cli)
    out = module.run_command(show_cli)[1]

    out = out.split()

    NAME_EXISTS = True if name in out else False
    NODE1_EXISTS = True if node1 in out else False
    NODE2_EXISTS = True if node2 in out else False


def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    action = module.params['pn_action']
    cli = shlex.split(cli)

    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="Cluster %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="Cluster %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="Cluster %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_cluster_node1=dict(type='str'),
            pn_cluster_node2=dict(type='str'),
            pn_validate=dict(type='bool'),
            pn_sync_timeout=dict(type='str'),
            pn_sync_offline_count=dict(type='str')
        )
    )

    # Accessing the parameters
    action = module.params['pn_action']
    command = 'cluster-' + action
    name = module.params['pn_name']
    cluster_node1 = module.params['pn_cluster_node1']
    cluster_node2 = module.params['pn_cluster_node2']
    validate = module.params['pn_validate']
    sync_timeout = module.params['pn_sync_timeout']
    sync_offline_count = module.params['pn_sync_offline_count']

    # Building the CLI command string
    cli = pn_cli(module)
    check_cli(module)
    cli += ' %s name %s ' % (command, name)

    if action == 'delete':
        if NAME_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='Cluster with name %s does not exist' % name
            )
    else:
        if action == 'create':
            if NAME_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='Cluster with name %s already exists' % name
                )
            if NODE1_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='Node %s already part of a cluster' % cluster_node1
                )
            if NODE2_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='Node %s already part of a cluster' % cluster_node2
                )

            cli += ' cluster-node-1 %s cluster-node-2 %s ' \
                   % (cluster_node1, cluster_node2)

            if validate is True:
                cli += ' validate '
            if validate is False:
                cli += ' no-validate '

        if action == 'modify':
            if NAME_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='Cluster with name %s does not exist' % name
                )

        if sync_timeout:
            cli += ' cluster-sync-timeout ' + sync_timeout

        if sync_offline_count:
            cli += ' cluster-sync-offline-count ' + sync_offline_count

    run_cli(module, cli)

if __name__ == '__main__':
    main()
