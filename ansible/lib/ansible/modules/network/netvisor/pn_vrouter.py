#!/usr/bin/python
""" PN CLI vrouter-create/vrouter-delete/vrouter-modify """
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
module: pn_vrouter
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/delete/modify a vrouter.
description:
  - Execute vrouter-create, vrouter-delete, vrouter-modify command.
  - Each fabric, cluster, standalone switch, or virtual network (VNET) can
    provide its tenants with a virtual router (vRouter) service that forwards
    traffic between networks and implements Layer 3 protocols.
  - C(create) creates a new vRouter service.
  - C(delete) deletes a vRouter service.
  - C(modify) modifies a vRouter service.
  - Certain parameters are allowed with certain actions only.
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - vRouter configuration command.
    required: true
    choices: ['create', 'delete', 'modify']
    type: str
  pn_name:
    description:
      - Specify the name of the vRouter.
    required: true
    type: str
  pn_vnet:
    description:
      - Specify the name of the vnet. Required for create.
      - Format "fabric-name-global"
    type: str
  pn_vnet_service_type:
    description:
      - Specify the type of vnet service.
    choices: ['dedicated', 'shared']
    type: str
  pn_service_state:
    description:
      - Enable/Disable vRouter service. Enabled by default.
    choices: ['enable', 'disable']
    type: str
  pn_shared_vnet_mgr:
    description:
      - vnet-manager to share with if shared service.
    type: str
  pn_location:
    description:
      - Location of the service.
    type: str
  pn_storage_pool:
    description:
      - Storage pool assigned to the service.
    type: str
  pn_router_type:
    description:
      - Specify if the vRouter uses software or hardware.
    choices: ['hardware', 'software']
    type: str
  pn_hw_vrrp_id:
    description:
      - Specify the VRRP ID for the hardware vrouter.
    type: str
  pn_router_id:
    description:
      - Specify the vRouter IP address.
    type: str
  pn_proto_multi:
    description:
      - Multicast protocol.
    type: str
    choices: ['none', 'dvmrp', 'pim-ssm']
  pn_bgp_as:
    description:
      - Specify the Autonomous System Number(ASN) if the vRouter runs Border
        Gateway Protocol(BGP).
    type: str
  pn_bgp_redistribute:
    description:
      - BGP route redistribution - static, connected, rip, ospf.
    type: str
  pn_bgp_redist_static_metric:
    description:
      - Metric for redistributing BGP static routes.
    type: str
  pn_bgp_redist_connected_metric:
    description:
      - Metric for redistributing BGP connected routes.
    type: str
  pn_bgp_redist_rip_metric:
    description:
      - Metric for redistributing BGP RIP routes.
    type: str
  pn_bgp_redist_ospf_metric:
    description:
      - Metric for redistributing BGP OSPF routes.
    type: str
  pn_bgp_redist_static_routemap:
    description:
      - Routemap for redistributing BGP static routes.
    type: str
  pn_bgp_redist_connected_routemap:
    description:
      - Routemap for redistributing BGP connected routes.
    type: str
  pn_bgp_redist_ospf_routemap:
    description:
      - Routemap for redistributing BGP OSPF routes.
    type: str
  pn_bgp_max_paths:
    description:
      - Maximum BGP paths.
    type: str
  pn_bgp_cluster_id:
    description:
      - IP address for BGP cluster ID.
    type: str
  pn_bgp_ibgp_multipath:
    description:
      - Number of iBGP multipath connections.
    type: str
  pn_bgp_bestpath:
    description:
      - Best path for BGP.
    type: str
    choices: ['ignore', 'multipath-relax']
  pn_bgp_dampening:
    description:
      - Dampening for BGP routes.
    type: str
  pn_bgp_graceful_restart:
    description:
      - Restart BGP gracefully.
    type: bool
  pn_bgp_stalepath_time:
    description:
      - Interval before a BGP path becomes stale.
    type: str
  pn_bgp_scantime:
    description:
      - BGP scanner interval (seconds) - default 60.
    type: str
  pn_delayed_startup:
    description:
      - Delays forming peer adjacency on bootup.
    type: str
  pn_bgp_keepalive_interval:
    description:
      - BGP Keepalive interval (seconds) - default 60.
    type: str
  pn_bgp_holdtime:
    description:
      - BGP Holdtime (seconds) - default 180.
    type: str
  pn_bgp_distance_internal:
    description:
      - BGP distance for routes internal to AS.
    type: str
  pn_bgp_distance_external:
    description:
      - BGP distance for routes external to AS.
    type: str
  pn_bgp_distance_local:
    description:
      - BGP distance for local routes.
    type: str
  pn_rip_redistribute:
    description:
      - Redistribute RIP routes - static, connected, bgp, ospf.
    type: str
  pn_ospf_redistribute:
    description:
      - Redistribute OSPF routes - static, connected, rip, bgp.
    type: str
  pn_ospf_redist_static_metric:
    description:
      - Metric for OSPF redistribution of static routes.
    type: str
  pn_ospf_redist_static_metric_type:
    description:
      - Metric type for OSPF redistribution of static routes.
    type: str
  pn_ospf_redist_static_routemap:
    description:
      - Route map for OSPF redistribution of static routes.
    type: str
  pn_ospf_redist_connected_metric:
    description:
      - Metric for OSPF redistribution of connected routes.
    type: str
  pn_ospf_redist_connected_metric_type:
    description:
      - Metric type for OSPF redistribution of connected routes.
    type: str
  pn_ospf_redist_connected routemap:
    description:
      - Route map for OSPF redistribution of connected routes.
    type: str
  pn_ospf_redist_rip_metric:
    description:
      - Metric for OSPF redistribution of RIP routes.
    type: str
  pn_ospf_redist_rip_metric_type:
    description:
      - Metric type for OSPF redistribution of RIP routes.
    type: str
  pn_ospf_redist_bgp_metric:
    description:
      - Metric for OSPF redistribution of BGP routes.
    type: str
  pn_ospf_redist_bgp_metric_type:
    description:
      - Metric type for OSPF redistribution of BGP routes.
    type: str
  pn_ospf_redist_bgp_routemap:
    description:
      - Route map for OSPF redistribution of BGP routes.
    type: str
  pn_ospf_distance_external:
    description:
      - OSPF distance for external routes.
    type: str
  pn_ospf_distance_internal:
    description:
      - OSPF distance for inter-area routes.
    type: str
  pn_ospf_distance_local:
    description:
      - OSPF distance for intra-area routes.
    type: str
  pn_ospf_stub_router:
    description:
      - Advertise self as stub router temporary on startup.
    type: bool
  pn_ospf_stub_router_period:
    description:
      - Period to advertise self as stub router after startup.
    type: str
  pn_ospf_bfd:
    description:
      - Use BFD protocol for fault detection on all OSPF interfaces.
    type: str
  pn_vrrp_track_port:
    description:
      - Track port for VRRP.
    type: str
  pn_bgp_snmp:
    description:
      - Enable BGP SNMP MIB.
    type: bool
  pn_bgp_snmp_notif:
    description:
      - Enable BGP SNMP notifications.
    type: bool
  pn_ospf_snmp:
    description:
      - Enable OSPF SNMP MIB.
    type: bool
  pn_ospf_snmp_notif:
    description:
      - Enable OSPF SNMP notifications.
    type: bool
"""

EXAMPLES = """
- name: create vrouter
  pn_vrouter:
    pn_action: "create"
    pn_name: "spine1-vrouter"
    pn_vnet: "ansible-global"
    pn_router_id: "1.1.1.1"
    pn_router_type: "hardware"
    pn_hw_vrrp_id: "19"

- name: delete vrouter
  pn_vrouter:
    pn_action: "delete"
    pn_name: "spine1-vrouter"

- name: modify vrouter
  pn_vrouter:
    pn_action: "modify"
    pn_name: "spine1-vrouter"
    pn_router_id: "2.2.2.2"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

VROUTER_EXISTS = None
VROUTER_NAME_EXISTS = None


def pn_cli(module):
    """
    This method is to generate the cli portion to launch the Netvisor cli.
    It parses the username, password, switch parameters from module.
    :param module: The Ansible module to fetch username, password and switch
    :return: returns the cli string for further processing
    """
    cliswitch = module.params['pn_cliswitch']
    action = module.params['pn_action']

    cli = '/usr/bin/cli --quiet '

    if action == 'delete':
        cli += '-e '

    if cliswitch:
        cli += ' switch ' + cliswitch

    return cli


def check_cli(module):
    """
    This method checks for idempotency using the vrouter-show command.
    A switch can have only one vRouter configuration.
    If a vRouter already exists on the given switch, return VROUTER_EXISTS as
    True else False.
    If a vRouter with the given name exists(on a different switch), return
    VROUTER_NAME_EXISTS as True else False.

    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VROUTER_EXISTS, VROUTER_NAME_EXISTS
    """
    name = module.params['pn_name']
    show_cli = pn_cli(module)
    # Global flags
    global VROUTER_EXISTS, VROUTER_NAME_EXISTS

    # Get the name of the local switch
    location = show_cli + ' switch-setup-show format switch-name'
    location = shlex.split(location)
    out = module.run_command(location)[1]
    location = out.split()[1]

    # Check for any vRouters on the switch
    check_vrouter = show_cli + ' vrouter-show location %s ' % location
    check_vrouter += 'format name no-show-headers'
    check_vrouter = shlex.split(check_vrouter)
    out = module.run_command(check_vrouter)[1]

    VROUTER_EXISTS = True if out else False

    # Check for any vRouters with the given name
    show = show_cli + ' vrouter-show format name no-show-headers '
    show = shlex.split(show)
    out = module.run_command(show)[1]
    out = out.split()

    VROUTER_NAME_EXISTS = True if name in out else False


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
            msg="vRouter %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vRouter %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vRouter %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_vnet=dict(type='str'),
            pn_router_type=dict(type='str',
                                choices=['hardware', 'software']),
            pn_vnet_service_type=dict(type='str',
                                      choices=['dedicated', 'shared']),
            pn_service_state=dict(type='str',
                                  choices=['enable', 'disable']),
            pn_shared_vnet_mgr=dict(type='str'),
            pn_location=dict(type='str'),
            pn_storage_pool=dict(type='str'),
            pn_hw_vrrp_id=dict(type='str'),
            pn_router_id=dict(type='str'),
            pn_proto_multi=dict(type='str',
                                choices=['none', 'dvmrp', 'pip-ssm']),
            pn_bgp_as=dict(type='str'),
            pn_bgp_redistribute=dict(type='str'),
            pn_bgp_redist_static_metric=dict(type='str'),
            pn_bgp_redist_static_routemap=dict(type='str'),
            pn_bgp_redist_connected_metric=dict(type='str'),
            pn_bgp_redist_connected_routemap=dict(type='str'),
            pn_bgp_redist_rip_metric=dict(type='str'),
            pn_bgp_redist_ospf_metric=dict(type='str'),
            pn_bgp_redist_ospf_routemap=dict(type='str'),
            pn_bgp_cluster_id=dict(type='str'),
            pn_bgp_max_paths=dict(type='str'),
            pn_bgp_ibgp_multipath=dict(type='str'),
            pn_bgp_bestpath=dict(type='str',
                                 choices=['ignore', 'multipath-relax']),
            pn_bgp_dampening=dict(type='bool'),
            pn_bgp_graceful_restart=dict(type='bool'),
            pn_bgp_stalepath_time=dict(type='str'),
            pn_bgp_scantime=dict(type='str'),
            pn_bgp_delayed_startup=dict(type='str'),
            pn_bgp_keepalive_interval=dict(type='str'),
            pn_bgp_holdtime=dict(type='str'),
            pn_bgp_distance_internal=dict(type='str'),
            pn_bgp_distance_external=dict(type='str'),
            pn_bgp_distance_local=dict(type='str'),
            pn_rip_redistribute=dict(type='str'),
            pn_ospf_redistribute=dict(type='str'),
            pn_ospf_redist_static_metric=dict(type='str'),
            pn_ospf_redist_static_metric_type=dict(type='str',
                                                   choices=['1', '2']),
            pn_ospf_redist_static_routemap=dict(type='str'),
            pn_ospf_redist_connected_metric=dict(type='str'),
            pn_ospf_redist_connected_metric_type=dict(type='str',
                                                      choices=['1', '2']),
            pn_ospf_redist_connected_routemap=dict(type='str'),
            pn_ospf_redist_rip_metric=dict(type='str'),
            pn_ospf_redist_rip_metric_type=dict(type='str',
                                                choices=['1', '2']),
            pn_ospf_redist_bgp_metric=dict(type='str'),
            pn_ospf_redist_bgp_metric_type=dict(type='str',
                                                choices=['1', '2']),
            pn_ospf_redist_bgp_routemap=dict(type='str'),
            pn_ospf_distance_external=dict(type='str'),
            pn_ospf_distance_internal=dict(type='str'),
            pn_ospf_distance_local=dict(type='str'),
            pn_ospf_stub_router=dict(type='bool'),
            pn_ospf_stub_router_period=dict(type='str'),
            pn_ospf_default_information=dict(type='str'),
            pn_ospf_bfd=dict(type='bool'),
            pn_vrrp_track_port=dict(type='str'),
            pn_bgp_snmp=dict(type='bool'),
            pn_bgp_snmp_notif=dict(type='bool'),
            pn_ospf_snmp=dict(type='bool'),
            pn_ospf_snmp_notif=dict(type='bool')
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vrouter-' + action
    name = module.params['pn_name']
    vnet = module.params['pn_vnet']
    router_type = module.params['pn_router_type']
    vnet_service_type = module.params['pn_vnet_service_type']
    service_state = module.params['pn_service_state']
    shared_vnet_mgr = module.params['pn_shared_vnet_mgr']
    location = module.params['pn_location']
    storage_pool = module.params['pn_storage_pool']
    hw_vrrp_id = module.params['pn_hw_vrrp_id']
    router_id = module.params['pn_router_id']
    proto_multi = module.params['pn_proto_multi']
    bgp_as = module.params['pn_bgp_as']
    bgp_redistribute = module.params['pn_bgp_redistribute']
    bgp_redist_static_metric = module.params['pn_bgp_redist_static_metric']
    bgp_redist_connected_metric = \
        module.params['pn_bgp_redist_connected_metric']
    bgp_redist_rip_metric = module.params['pn_bgp_redist_rip_metric']
    bgp_redist_ospf_metric = module.params['pn_bgp_redist_ospf_metric']
    bgp_redist_static_routemap = module.params['pn_bgp_redist_static_routemap']
    bgp_redist_connected_routemap = \
        module.params['pn_bgp_redist_connected_routemap']
    bgp_redist_ospf_routemap = module.params['pn_bgp_redist_ospf_routemap']
    bgp_cluster_id = module.params['pn_bgp_cluster_id']
    bgp_max_paths = module.params['pn_bgp_max_paths']
    bgp_ibgp_multipath = module.params['pn_bgp_ibgp_multipath']
    bgp_bestpath = module.params['pn_bgp_bestpath']
    bgp_dampening = module.params['pn_bgp_dampening']
    bgp_graceful_restart = module.params['pn_bgp_graceful_restart']
    bgp_stalepath_time = module.params['pn_bgp_stalepath_time']
    bgp_scantime = module.params['pn_bgp_scantime']
    bgp_delayed_startup = module.params['pn_bgp_delayed_startup']
    bgp_keepalive_interval = module.params['pn_bgp_keepalive_interval']
    bgp_holdtime = module.params['pn_bgp_holdtime']
    bgp_distance_internal = module.params['pn_bgp_distance_internal']
    bgp_distance_external = module.params['pn_bgp_distance_external']
    bgp_distance_local = module.params['pn_bgp_distance_local']
    rip_redistribute = module.params['pn_rip_redistribute']
    ospf_redistribute = module.params['pn_ospf_redistribute']
    ospf_redist_static_metric = \
        module.params['pn_ospf_redist_static_metric']
    ospf_redist_static_metric_type = \
        module.params['pn_ospf_redist_static_metric_type']
    ospf_redist_connected_metric = \
        module.params['pn_ospf_redist_connected_metric']
    ospf_redist_connected_metric_type = \
        module.params['pn_ospf_redist_connected_metric_type']
    ospf_redist_rip_metric = module.params['pn_ospf_redist_rip_metric']
    ospf_redist_rip_metric_type = \
        module.params['pn_ospf_redist_rip_metric_type']
    ospf_redist_bgp_metric = module.params['pn_ospf_redist_bgp_metric']
    ospf_redist_bgp_metric_type = \
        module.params['pn_ospf_redist_bgp_metric_type']
    ospf_redist_static_routemap = \
        module.params['pn_ospf_redist_static_routemap']
    ospf_redist_connected_routemap = \
        module.params['pn_ospf_redist_connected_routemap']
    ospf_redist_bgp_routemap = module.params['pn_ospf_redist_bgp_routemap']
    ospf_distance_external = module.params['pn_ospf_distance_external']
    ospf_distance_internal = module.params['pn_ospf_distance_internal']
    ospf_distance_local = module.params['pn_ospf_distance_local']
    ospf_stub_router = module.params['pn_ospf_stub_router']
    ospf_stub_router_period = module.params['pn_ospf_stub_router_period']
    ospf_bfd = module.params['pn_ospf_bfd']
    vrrp_track_port = module.params['pn_vrrp_track_port']
    bgp_snmp = module.params['pn_bgp_snmp']
    bgp_snmp_notif = module.params['pn_bgp_snmp_notif']
    ospf_snmp = module.params['pn_ospf_snmp']
    ospf_snmp_notif = module.params['pn_ospf_snmp_notif']
    ospf_default_information = module.params['pn_ospf_default_information']

    # Building the CLI command string
    cli = pn_cli(module)
    if action == 'delete':
        check_cli(module)
        if VROUTER_NAME_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vRouter with name %s does not exist' % name
            )
        cli += ' %s name %s ' % (command, name)

    else:
        check_cli(module)
        if action == 'modify':
            if VROUTER_NAME_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vRouter with name %s does not exist' % name
                )
            cli += ' %s name %s ' % (command, name)

        if action == 'create':
            if VROUTER_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='Maximum number of vRouters has been reached on this '
                        'switch'
                )
            if VROUTER_NAME_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='vRouter with name %s already exists' % name
                )
            cli += ' %s name %s vnet %s router-type %s ' \
                   % (command, name, vnet, router_type)

        if hw_vrrp_id:
            cli += ' hw-vrrp-id ' + hw_vrrp_id

        if location:
            cli += ' location ' + location

        if proto_multi:
            cli += ' proto-multi ' + proto_multi

        if storage_pool:
            cli += ' storage-pool ' + storage_pool

        if action == 'create':
            if vnet_service_type:
                cli += ' %s-vnet-service ' % vnet_service_type
            if vnet_service_type == 'shared' and shared_vnet_mgr:
                cli += 'shared-vnet-mgr %s ' % shared_vnet_mgr

        if service_state:
            cli += service_state

        if router_id:
            cli += ' router-id ' + router_id

        if vrrp_track_port:
            cli += ' vrrp-track-port ' + vrrp_track_port

        if bgp_as:
            cli += ' bgp-as ' + bgp_as
        if bgp_redistribute:
            cli += ' bgp-redistribute ' + bgp_redistribute
        if bgp_redist_static_metric:
            cli += ' bgp-redist-static-metric ' + bgp_redist_static_metric
        if bgp_redist_connected_metric:
            cli += ' bgp-redist-connected-metric ' \
                   + bgp_redist_connected_metric
        if bgp_redist_rip_metric:
            cli += ' bgp-redist-rip-metric ' + bgp_redist_rip_metric
        if bgp_redist_ospf_metric:
            cli += ' bgp-redist-ospf-metric ' + bgp_redist_ospf_metric
        if bgp_max_paths:
            cli += ' bgp-max-paths ' + bgp_max_paths
        if bgp_cluster_id:
            cli += ' bgp-cluster-id ' + bgp_cluster_id
        if bgp_ibgp_multipath:
            cli += ' bgp-ibgp-multipath ' + bgp_ibgp_multipath
        if bgp_bestpath:
            cli += ' bgp-bestpath-as-path ' + bgp_bestpath
        if bgp_dampening is True:
            cli += ' bgp-dampening '
        if bgp_graceful_restart is True:
            cli += ' bgp-graceful-restart '
        if bgp_stalepath_time:
            cli += ' bgp-stalepath-time ' + bgp_stalepath_time
        if bgp_scantime:
            cli += ' bgp-scantime ' + bgp_scantime
        if bgp_delayed_startup:
            cli += ' bgp-delayed-startup ' + bgp_delayed_startup
        if bgp_keepalive_interval:
            cli += ' bgp-keepalive-interval ' + bgp_keepalive_interval
        if bgp_holdtime:
            cli += ' bgp-holdtime ' + bgp_holdtime
        if bgp_distance_external:
            cli += ' bgp-distance-external ' + bgp_distance_external
        if bgp_distance_internal:
            cli += ' bgp-distance-internal ' + bgp_distance_internal
        if bgp_distance_local:
            cli += ' bgp-distance-local ' + bgp_distance_local
        if bgp_snmp is True:
            cli += ' bgp-snmp '
        if bgp_snmp_notif is True:
            cli += ' bgp-snmp-notification '

        if rip_redistribute:
            cli += ' rip-redistribute ' + rip_redistribute

        if ospf_redistribute:
            cli += ' ospf-redistribute ' + ospf_redistribute
        if ospf_redist_static_metric:
            cli += ' ospf-redist-static-metric ' + ospf_redist_static_metric
        if ospf_redist_static_metric_type:
            cli += ' ospf-redist-static-metric-type ' \
                   + ospf_redist_static_metric_type
        if ospf_redist_connected_metric:
            cli += ' ospf-redist-connected-metric ' \
                   + ospf_redist_connected_metric
        if ospf_redist_connected_metric_type:
            cli += ' ospf-redist-connected-metric-type ' \
                   + ospf_redist_connected_metric_type
        if ospf_redist_rip_metric:
            cli += ' ospf-redist-rip-metric ' + ospf_redist_rip_metric
        if ospf_redist_rip_metric_type:
            cli += ' ospf-redist-rip-metric-type ' \
                   + ospf_redist_rip_metric_type
        if ospf_redist_bgp_metric:
            cli += ' ospf-redist-bgp-metric ' + ospf_redist_bgp_metric
        if ospf_redist_bgp_metric_type:
            cli += ' ospf-redist-bgp-metric-type ' \
                   + ospf_redist_bgp_metric_type
        if ospf_distance_external:
            cli += ' ospf-distance-external ' + ospf_distance_external
        if ospf_distance_internal:
            cli += ' ospf-distance-internal ' + ospf_distance_internal
        if ospf_distance_local:
            cli += ' ospf-distance-local ' + ospf_distance_local
        if ospf_stub_router is True:
            cli += ' ospf-stub-router-on-startup '
        if ospf_stub_router_period:
            cli += ' ospf-stub-router-on-start-up-period ' \
                   + ospf_stub_router_period
        if ospf_bfd is True:
            cli += ' ospf-bfd-all-if '
        if ospf_snmp is True:
            cli += ' ospf-snmp '
        if ospf_snmp_notif:
            cli += ' ospf-snmp-notification '

        if action == 'modify':
            if bgp_redist_static_routemap:
                cli += ' bgp-redist-static-routemap ' \
                       + bgp_redist_static_routemap
            if bgp_redist_connected_routemap:
                cli += ' bgp-redist-connected-routemap ' \
                       + bgp_redist_connected_routemap
            if bgp_redist_ospf_routemap:
                cli += ' bgp-redist-ospf-routemap ' + bgp_redist_ospf_routemap
            if ospf_redist_static_routemap:
                cli += ' ospf-redist-static-routemap ' \
                       + ospf_redist_static_routemap
            if ospf_redist_connected_routemap:
                cli += ' ospf-redist-connected-routemap ' \
                       + ospf_redist_connected_routemap
            if ospf_redist_bgp_routemap:
                cli += ' ospf-redist-bgp-routemap ' + ospf_redist_bgp_routemap

            if ospf_default_information:
                cli += ' ospf-default-information ' + ospf_default_information

    run_cli(module, cli)

if __name__ == '__main__':
    main()
