#!/usr/bin/python
""" PN CLI trunk-create/trunk-delete/trunk-modify """
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
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli

DOCUMENTATION = """
---
module: pn_trunk
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2.0
short_description: CLI command to create/delete/modify a trunk.
description:
  - Execute trunk-create, trunk-delete or trunk-modify command.
options:
  pn_cliswitch:
    description:
      - Target switch to run the cli on.
    required: False
    type: str
  pn_action:
    description:
      - The Trunk configuration command.
    required: true
    choices: ['create', 'delete', 'modify']
    type: str
  pn_name:
    description:
      - Name for the trunk configuration.
    required: true
    type: str
  pn_trunk_id:
    description:
      - Trunk ID number of physical interface.
    type: str
  pn_physical_ports:
    description:
      - Physical ports list.
    type: str
  pn_bezel_ports:
    description:
      - Bezel ports list.
    type: str
  pn_speed:
    description:
      - Specify the port speed or disable the port.
    choices: ['disable', '10m', '100m', '1g', '2.5g', '10g', '25g', '40g',
              '50g', '100g']
    type: str
  pn_egress_rate_limit:
    description:
      - Specify an egress port data rate limit for the configuration.
    type: str
  pn_autoneg:
    description:
      - Physical port auto-negotiation.
    type: bool
  pn_jumbo:
    description
      - Specify if the port can receive jumbo frames.
    type: bool
  pn_lacp_mode:
    description:
      - LACP mode of the physical port.
    choices: ['off', 'passive', 'active']
    type: str
  pn_lacp_priority:
    description
      - LACP priority between 1 and 65535, default 32768.
    type: str
  pn_lacp_timeout:
    description:
      - LACP time out as slow or fast, default slow.
    choices: ['slow', 'fast']
    type: str
  pn_lacp_fallback:
    description:
      - LACP fallback mode as bundled or individual.
    choices: ['bundle', 'individual']
    type: str
  pn_lacp_fallback_timeout:
    description:
      - LACP fallback timeout between 30 and 60 seconds, default 50 seconds.
    type: str
  pn_reflect:
    description:
      - Physical port reflection.
    type: bool
  pn_edge_switch:
    description:
      - Physical port edge switch.
    type: bool
  pn_pause:
    description:
      - Physical port pause.
    type: bool
  pn_description:
    description:
      - Physical port description.
    type: str
  pn_loopback:
    description;
      - Physical port loopback.
    type: bool
  pn_vxlan_termination:
    description:
      - Physical port VxLAN termination.
    type: bool
  pn_unkown_ucast_level:
    description:
      - Unkown unicast level in %, default 30%.
    type: str
  pn_unkown_mcast_level:
    description:
      - Unkown multicast level in %, default 30%.
    type: str
  pn_broadcast_level:
    description:
      - Broadcast level in %, default 30%.
    type: str
  pn_port_macaddr:
    description:
      - Physical port MAC address.
    type: str
  pn_loop_vlans:
    description:
      - Specify a list of looping vlans.
    type: str
  pn_routing:
    description:
      - Specify if the port participates in routing.
    type: bool
  pn_host:
    description:
      - Host facing port control setting.
    type: str
    choices: ['enable', 'disable']
  pn_dscp_map:
    description:
      - DSCP map name to enable on the port.
    type: str
  pn_local_switching:
    description:
      - no-local-switching port cannot bridge traffic to another
        no-local-switching port.
    type: bool
  pn_allowed_tpid:
    description:
      - Allowed TPID in addition to 0x8100 on vLAN header.
    type: str
    choices: ['q-in-q', 'q-in-q-old']
  pn_fabric_guard:
    description:
      - Fabric guard configuration.
    type: bool
"""

EXAMPLES = """
- name: create trunk
  pn_trunk:
    pn_action: 'create'
    pn_name: 'spine-to-leaf'
    pn_ports: '11,12,13,14'

- name: delete trunk
  pn_trunk:
    pn_action: 'delete'
    pn_name: 'spine-to-leaf'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: the set of responses from the trunk command.
  returned: always
  type: list
stderr:
  description: the set of error responses from the trunk command.
  returned: on error
  type: list
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""
TRUNK_EXISTS = None
TRUNK_ID_EXISTS = None


def check_cli(module):
    """
    This method checks for idempotency using the trunk-show command.
    If a trunk with given name exists, return TRUNK_EXISTS as True else False.
    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: TRUNK_EXISTS, TRUNK_ID_EXISTS
    """
    name = module.params['pn_name']
    trunk_id = module.params['pn_trunk_id']
    switch = module.params['pn_cliswitch']
    show_cli = pn_cli(module, switch)
    # Global flags
    global TRUNK_EXISTS, TRUNK_ID_EXISTS

    show_cli += ' trunk-show format switch,name,trunk-id no-show-headers'
    show_cli = shlex.split(show_cli)
    out = module.run_command(show_cli)[1]

    out = out.split()

    TRUNK_EXISTS = True if name in out else False
    if trunk_id:
        TRUNK_ID_EXISTS = True if trunk_id in out else False


def get_ports(module):
    cli = pn_cli(module, switch_local=True)
    phy_ports = module.params['pn_physical_ports']
    bezel_ports = module.params['pn_bezel_ports']

    if phy_ports:
        return phy_ports

    if bezel_ports:
        cli += ' port-show bezel-port %s format port, no-show-headers ' % (bezel_ports)
        cli = shlex.split(cli)
        out = module.run_command(cli)[1]
        if out is not None:
            out = out.split()
            return ','.join(out)


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
        module.exit_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="Trunk %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="Trunk %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="Trunk %s operation completed" % action,
            changed=True
        )


def main():
    """ This portion is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                        choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_trunk_id=dict(type='str'),
            pn_bezel_ports=dict(type='str'),
            pn_physical_ports=dict(type='str'),
            pn_speed=dict(type='str',
                          choices=['disable', '10m', '100m', '1g', '2.5g',
                                   '10g', '25g', '40g', '50g', '100g']),
            pn_egress_rate_limit=dict(type='str'),
            pn_autoneg=dict(type='bool'),
            pn_jumbo=dict(type='bool'),
            pn_lacp_mode=dict(type='str',
                              choices=['off', 'passive', 'active']),
            pn_lacp_priority=dict(type='int'),
            pn_lacp_timeout=dict(type='str'),
            pn_lacp_fallback=dict(type='str',
                                  choices=['bundle', 'individual']),
            pn_lacp_fallback_timeout=dict(type='str'),
            pn_reflect=dict(type='bool'),
            pn_edge_switch=dict(type='bool'),
            pn_pause=dict(type='bool'),
            pn_description=dict(type='str'),
            pn_loopback=dict(type='bool'),
            pn_vxlan_termination=dict(type='bool'),
            pn_unknown_ucast_level=dict(type='str'),
            pn_unknown_mcast_level=dict(type='str'),
            pn_broadcast_level=dict(type='str'),
            pn_port_macaddr=dict(type='str'),
            pn_loop_vlans=dict(type='str'),
            pn_routing=dict(type='bool'),
            pn_host=dict(type='str',
                         choices=['enable', 'disable']),
            pn_dscp_map=dict(type='str'),
            pn_local_switching=dict(type='bool'),
            pn_allowed_tpid=dict(type='bool',
                                 choices=['q-in-q', 'q-in-q-old']),
            pn_fabric_guard=dict(type='bool')
        ),
        mutually_exclusive=["pn_physical_ports", "pn_bezel_ports"]
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    action = module.params['pn_action']
    command = ' trunk-' + action
    name = module.params['pn_name']
    trunk_id = module.params['pn_trunk_id']
    bezel_ports = module.params['pn_bezel_ports']
    physical_ports = module.params['pn_physical_ports']
    speed = module.params['pn_speed']
    egress_rate_limit = module.params['pn_egress_rate_limit']
    autoneg = module.params['pn_autoneg']
    jumbo = module.params['pn_jumbo']
    lacp_mode = module.params['pn_lacp_mode']
    lacp_priority = module.params['pn_lacp_priority']
    lacp_timeout = module.params['pn_lacp_timeout']
    lacp_fallback = module.params['pn_lacp_fallback']
    lacp_fallback_timeout = module.params['pn_lacp_fallback_timeout']
    reflect = module.params['pn_reflect']
    edge_switch = module.params['pn_edge_switch']
    pause = module.params['pn_pause']
    description = module.params['pn_description']
    loopback = module.params['pn_loopback']
    vxlan_termination = module.params['pn_vxlan_termination']
    unknown_ucast_level = module.params['pn_unknown_ucast_level']
    unknown_mcast_level = module.params['pn_unknown_mcast_level']
    broadcast_level = module.params['pn_broadcast_level']
    port_macaddr = module.params['pn_port_macaddr']
    loop_vlans = module.params['pn_loop_vlans']
    routing = module.params['pn_routing']
    host = module.params['pn_host']
    dscp_map = module.params['pn_dscp_map']
    local_switching = module.params['pn_local_switching']
    allowed_tpid = module.params['pn_allowed_tpid']
    fabric_guard = module.params['pn_fabric_guard']


    # Building the CLI command string
    cli = pn_cli(module, switch)
    check_cli(module)
    ports = get_ports(module)

    cli += ' %s name %s ' % (command, name)

    if action == 'delete':
        if TRUNK_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='Trunk with name %s does not exist' % name
            )
        if trunk_id:
            if TRUNK_ID_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='Trunk with id %s does not exist' % trunk_id
                )
            cli += ' trunk-id ' + trunk_id
    else:
        if action == 'create':
            if TRUNK_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='Trunk with name %s already exists' % name
                )

        if action == 'modify':
            if TRUNK_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='Trunk with name %s does not exist' % name
                )
            if trunk_id:
                if TRUNK_ID_EXISTS is False:
                    module.exit_json(
                        skipped=True,
                        msg='Trunk with id %s does not exist' % trunk_id
                    )
                cli += ' trunk-id ' + trunk_id

        if ports:
            cli += ' ports ' + ports

        if speed:
            cli += ' speed ' + speed

        if egress_rate_limit:
            cli += ' egress-rate-limit ' + egress_rate_limit

        if autoneg is True:
            cli += ' autoneg '
        if autoneg is False:
            cli += ' no-autoneg '

        if jumbo is True:
            cli += ' jumbo '
        if jumbo is False:
            cli += ' no-jumbo '

        if lacp_mode:
            cli += ' lacp-mode ' + lacp_mode

        if lacp_priority:
            cli += ' lacp-priority ' + lacp_priority

        if lacp_timeout:
            cli += ' lacp-timeout ' + lacp_timeout

        if lacp_fallback:
            cli += ' lacp-fallback ' + lacp_fallback

        if lacp_fallback_timeout:
            cli += ' lacp-fallback-timeout ' + lacp_fallback_timeout

        if reflect is True:
            cli += ' reflect '
        if reflect is False:
            cli += ' no-reflect '

        if edge_switch is True:
            cli += ' edge-switch '
        if edge_switch is False:
            cli += ' no-edge-switch '

        if pause is True:
            cli += ' pause '
        if pause is False:
            cli += ' no-pause '

        if description:
            cli += ' description ' + description

        if loopback is True:
            cli += ' loopback '
        if loopback is False:
            cli += ' no-loopback '

        if vxlan_termination is True:
            cli += ' vxlan-termination '
        if vxlan_termination is False:
            cli += ' no-vxlan-termination '

        if unknown_ucast_level:
            cli += ' unknown-ucast-level ' + unknown_ucast_level

        if unknown_mcast_level:
            cli += ' unknown-mcast-level ' + unknown_mcast_level

        if broadcast_level:
            cli += ' broadcast-level ' + broadcast_level

        if port_macaddr:
            cli += ' port-mac-address ' + port_macaddr

        if loop_vlans:
            cli += ' loop-vlans ' + loop_vlans

        if routing is True:
            cli += ' routing '
        if routing is False:
            cli += ' no-routing '

        if host:
            cli += ' host-' + host

        if dscp_map:
            cli += 'dscp-map ' + dscp_map

        if local_switching is True:
            cli += ' local-switching '
        if local_switching is False:
            cli += ' no-local-switching '

        if allowed_tpid:
            cli += ' allowed-tpid ' + allowed_tpid

        if fabric_guard is True:
            cli += ' fabric-guard '
        if fabric_guard is False:
            cli += ' no-fabric-guard '

    run_cli(module, cli)

if __name__ == '__main__':
    main()
