#!/usr/bin/python
""" PN-CLI vrouter-bgp-add/vrouter-bgp-remove/vrouter-bgp-modify """
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
module: pn_vrouter_bgp
author: "Pluribus Networks"
version: 2.0
short_description: CLI command to add/remove/modify vrouter-bgp.
description:
  - Execute vrouter-bgp-add, vrouter-bgp-remove, vrouter-bgp-modify command.
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
      - Target switch(es) to run the cli on.
    required: False
    type: str
  pn_action:
    description:
      - vRouter BGP config command.
    required: True
    choices: ['add', 'remove', 'modify']
    type: str
  pn_vrouter:
    description:
      - Name of the vRouter.
    required: True
    type: str
  pn_neighbor:
    description:
      - Specify a neighbor IP address to use for BGP.
    type: str
  pn_remote_as:
    description:
      - BGP remote AS number from 1 and 4294967295.
    type: str
  pn_next_hop_self:
    description:
      - BGP next-hop is self or not.
    type: bool
  pn_password:
    description:
      - Password for MD5 BGP..
    type: str
  pn_ebgp_multihop:
    description:
      - Value for external BGP from 1 to 255.
    type: str
  pn_update_src:
    description:
      - IP address of BGP packets required for peering over
        loopback interface.
    type: str
  pn_prefix_list_in:
    description:
      - Prefixes used for filtering incoming packets..
    type: str
  pn_prefix_list_out:
    description:
      - Prefixes for filtering outgoing packets.
    type: str
  pn_route_reflector:
    description:
      - Set as route reflector client.
    type: bool
  pn_override_capability:
    description:
      - Specify if you want to override capability.
    type: bool
  pn_soft_reconfig:
    description:
      - Specify if you want a soft reset to reconfigure of inbound traffic.
    type: bool
  pn_max_prefix:
    description:
      - Specify the maximum number of prefixes.
    type: int
  pn_max_prefix_warn:
    description:
      - Specify if you want a warning message when the maximum number of
        prefixes is exceeded.
    type: bool
  pn_bfd:
    description:
      - BFD protocol support for fault detection.
    type: bool
  pn_bfd_multihop:
    description:
      - Always use BFD multi-hop port for fault detection.
    type: bool
  pn_multiprotocol:
    description:
      - Multi-protocol features.
    choices: ['ipv4-unicast', 'ipv6-unicast']
    type: str
  pn_weight:
    description:
      - Default weight value between 0 and 65535 for the neighbor
        routes.
    type: str
  pn_default_originate:
    description:
      - Announce default routes to the neighbor or not.
    type: bool
  pn_keepalive_inteval:
    description:
      - BGP neighbor keepalive interval in seconds.
    type: str
  pn_holdtime:
    description:
      - BGP neighbor holdtime in seconds.
    type: str
  pn_send_community:
    description:
      - Send any community attribute to neighbor.
    type: str
  pn_route_map_in:
    description:
      - Inbound route map for neighbor.
    type: str
  pn_route_map_out:
    description:
      - Outbound route map for neighbor.
    type: str
  pn_allowas_in:
    description:
      - Allow/reject routes with local AS in AS_PATH.
    type: str
  pn_interface:
    description:
      - Interface to reach the neighbor.
    type: str
"""

EXAMPLES = """
- name: "Add BGP to vRouter"
  pn_vrouter_bgp:
    pn_action: 'add'
    pn_vrouter: 'ansible-vrouter'
    pn_neighbor: '104.104.104.1'
    pn_remote_as: 65000
    pn_next_hop: false
    pn_bfd: true

- name: "Remove BGP from a vRouter"
  pn_vrouter_bgp:
    pn_action: 'remove'
    pn_name: 'ansible-vrouter'
    pn_neighbor: '104.104.104.1'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: the set of responses from the vrouter bpg
  config command.
  returned: always
  type: list
stderr:
  description: the set of error responses from the vrouter bgp
  config command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the
  target.
  returned: always
  type: bool
"""


VROUTER_EXISTS = None
NEIGHBOR_EXISTS = None


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
    This method checks if vRouter exists on the target node.
    This method also checks for idempotency using the vrouter-bgp-show command.
    If the given vRouter exists, return VROUTER_EXISTS as True else False.
    If a BGP neighbor with the given ip exists on the given vRouter,
    return NEIGHBOR_EXISTS as True else False.

    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VROUTER_EXISTS, NEIGHBOR_EXISTS
    """
    vrouter = module.params['pn_vrouter']
    neighbor = module.params['pn_neighbor']
    show_cli = pn_cli(module)
    # Global flags
    global VROUTER_EXISTS, NEIGHBOR_EXISTS

    cliswitch = module.params['pn_cliswitch']
    if cliswitch:
        show_cli = show_cli.replace('switch', '')
        show_cli = show_cli.replace(cliswitch, '')

    # Check for vRouter
    check_vrouter = show_cli + ' vrouter-show format name no-show-headers '
    check_vrouter = shlex.split(check_vrouter)
    out = module.run_command(check_vrouter)[1]
    out = out.split()

    VROUTER_EXISTS = True if vrouter in out else False

    # Check for BGP neighbors
    check_neighbor = show_cli + ' vrouter-bgp-show vrouter-name %s ' % vrouter
    check_neighbor += 'format neighbor no-show-headers'
    check_neighbor = shlex.split(check_neighbor)
    out = module.run_command(check_neighbor)[1]
    out = out.split()

    NEIGHBOR_EXISTS = True if neighbor in out else False


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
            msg="vRouter BGP %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vRouter BGP %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vRouter BGP %s operation completed" % action,
            changed=True
        )


def main():
    """ This portion is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove', 'modify']),
            pn_vrouter=dict(required=True, type='str'),
            pn_neighbor=dict(type='str'),
            pn_remote_as=dict(type='str'),
            pn_next_hop_self=dict(type='bool'),
            pn_password=dict(type='str'),
            pn_ebgp_multihop=dict(type='str'),
            pn_update_src=dict(type='str'),
            pn_prefix_list_in=dict(type='str'),
            pn_prefix_list_out=dict(type='str'),
            pn_route_reflector=dict(type='bool'),
            pn_override_capability=dict(type='bool'),
            pn_soft_reconfig=dict(type='bool'),
            pn_max_prefix=dict(type='str'),
            pn_max_prefix_warn=dict(type='bool'),
            pn_bfd=dict(type='bool'),
            pn_bfd_multihop=dict(type='bool'),
            pn_multiprotocol=dict(type='str',
                                  choices=['ipv4-unicast', 'ipv6-unicast']),
            pn_weight=dict(type='str'),
            pn_default_originate=dict(type='bool'),
            pn_keepalive_interval=dict(type='str'),
            pn_holdtime=dict(type='str'),
            pn_send_community=dict(type='bool'),
            pn_route_map_in=dict(type='str'),
            pn_route_map_out=dict(type='str'),
            pn_allowas_in=dict(type='bool'),
            pn_interface=dict(type='str')
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vrouter-bgp-' + action
    vrouter = module.params['pn_vrouter']
    neighbor = module.params['pn_neighbor']
    remote_as = module.params['pn_remote_as']
    next_hop_self = module.params['pn_next_hop_self']
    password = module.params['pn_password']
    ebgp_multihop = module.params['pn_ebgp_multihop']
    prefix_list_in = module.params['pn_prefix_list_in']
    prefix_list_out = module.params['pn_prefix_list_out']
    route_reflector = module.params['pn_route_reflector']
    override_capability = module.params['pn_override_capability']
    soft_reconfig = module.params['pn_soft_reconfig']
    max_prefix = module.params['pn_max_prefix']
    max_prefix_warn = module.params['pn_max_prefix_warn']
    bfd = module.params['pn_bfd']
    bfd_multihop = module.params['pn_bfd_multihop']
    multiprotocol = module.params['pn_multiprotocol']
    weight = module.params['pn_weight']
    default_originate = module.params['pn_default_originate']
    keepalive_interval = module.params['pn_keepalive_interval']
    holdtime = module.params['pn_holdtime']
    send_community = module.params['pn_send_community']
    route_map_in = module.params['pn_route_map_in']
    route_map_out = module.params['pn_route_map_out']
    allowas_in = module.params['pn_allowas_in']
    interface = module.params['pn_interface']
    update_src = module.params['pn_update_src']

    # Building the CLI command string
    cli = pn_cli(module)
    check_cli(module)

    if action == 'remove':
        if VROUTER_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter %s does not exist' % vrouter
            )
        if NEIGHBOR_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='BGP neighbor with IP %s does not exist on %s'
                    % (neighbor, vrouter)
            )
        cli += ' %s vrouter-name %s neighbor %s ' \
               % (command, vrouter, neighbor)

    else:

        if action == 'add':
            if VROUTER_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter %s does not exist' % vrouter
                )
            if NEIGHBOR_EXISTS is True:
                module.exit_json(
                      skipped=True,
                      msg='BGP neighbor with IP %s already exists on %s'
                          % (neighbor, vrouter)
                )

        if action == 'modify':
            if VROUTER_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter %s does not exists' % vrouter
                )
            if NEIGHBOR_EXISTS is False:
                module.exit_json(
                   skipped=True,
                   msg='BGP neighbor with IP %s does not exist on %s'
                       % (neighbor, vrouter)
                )

        cli += ' %s vrouter-name %s neighbor %s ' \
               % (command, vrouter, neighbor)

        if remote_as:
            cli += ' remote-as ' + remote_as

        if next_hop_self is True:
            cli += ' next-hop-self '
        if next_hop_self is False:
            cli += ' no-next-hop-self '

        if password:
            cli += ' password ' + password

        if ebgp_multihop:
            cli += ' ebgp-multihop ' + ebgp_multihop

        if update_src:
            cli += ' update-source ' + update_src

        if prefix_list_in:
            cli += ' prefix-list-in ' + prefix_list_in

        if prefix_list_out:
            cli += ' prefix-list-out ' + prefix_list_out

        if route_reflector is True:
            cli += ' route-reflector-client '
        if route_reflector is False:
            cli += ' no-route-reflector-client '

        if override_capability is True:
            cli += ' override-capability '
        if override_capability is False:
            cli += ' no-override-capability '

        if soft_reconfig is True:
            cli += ' soft-reconfig-inbound '
        if soft_reconfig is False:
            cli += ' no-soft-reconfig-inbound '

        if max_prefix:
            cli += ' max-prefix ' + max_prefix

        if max_prefix_warn is True:
            cli += ' max-prefix-warn-only '
        if max_prefix_warn is False:
            cli += ' no-max-prefix-warn-only '

        if bfd is True:
            cli += ' bfd '
        if bfd is False:
            cli += ' no-bfd '

        if bfd_multihop is True:
            cli += ' bfd-multihop '
        if bfd_multihop is False:
            cli += ' no-bfd-multihop '

        if multiprotocol:
            cli += ' multi-protocol ' + multiprotocol

        if weight:
            cli += ' weight ' + weight

        if default_originate is True:
            cli += ' default-originate '
        if default_originate is False:
            cli += ' no-default-originate '

        if keepalive_interval:
            cli += ' neighbor-keepalive-interval ' + keepalive_interval

        if holdtime:
            cli += ' neighbor-holdtime ' + holdtime

        if send_community is True:
            cli += ' send-community '
        if send_community is False:
            cli += ' no-send-community '

        if route_map_in:
            cli += ' route-map-in ' + route_map_in

        if route_map_out:
            cli += ' route-map-out ' + route_map_out

        if allowas_in is True:
            cli += ' allowas-in '
        if allowas_in is False:
            cli += ' no-allowas-in '

        if interface:
            cli += ' interface ' + interface

    run_cli(module, cli)

if __name__ == '__main__':
    main()
