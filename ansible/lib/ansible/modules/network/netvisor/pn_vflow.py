#!/usr/bin/python
""" PN CLI vflow-create/modify/delete """

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


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: pn_vflow
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version_added: "2.7"
short_description: CLI command to create/modify/delete vflow.
description:
  - C(create): create a virtual flow definition for L2 or L3 IP
  - C(modify): modify a virtual flow
  - C(delete): delete a virtual flow definition for L2 or L3 IP
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  state:
    description:
      - State the action to perform. Use 'present' to create vflow and
        'absent' to delete vflow 'update' to modify the vflow.
    required: True
  pn_vxlan_proto:
    description:
      - protocol type for the VXLAN
    required: false
    choices: ['tcp', 'udp', 'icmp', 'igmp', 'ip', 'icmpv6']
  pn_out_port:
    description:
      - outgoing port for the vFlow
    required: false
    type: str
  pn_egress_tunnel:
    description:
      - tunnel for egress traffic
    required: false
    type: str
  pn_scope:
    description:
      - scope is local or fabric
    required: false
    choices: ['local', 'fabric']
  pn_dur:
    description:
      - minimum duration required for the flow to be captured (in seconds).
    required: false
    type: str
  pn_vxlan:
    description:
      - name of the VXLAN
    required: false
    type: str
  pn_metadata:
    description:
      - metadata number for the vflow
    required: false
    type: str
  pn_bd:
    description:
      - Bridge Domain for the vFlow
    required: false
    type: str
  pn_stp_state:
    description:
      - stp state
    required: false
    choices: ['Disabled', 'Discarding', 'Learning', 'Forwarding']
  pn_vlan:
    description:
      - VLAN for the vFlow
    required: false
    type: str
  pn_transient:
    description:
      - capture transient flows
    required: false
    type: bool
  pn_action_to_ecmp_group_value:
    description:
      - ECMP group for packet redirection
    required: false
    type: str
  pn_vxlan_ether_type:
    description:
      - EtherType for the VXLAN
    required: false
    choices: ['ipv4', 'arp', 'wake', 'rarp', 'vlan', 'ipv6', 'lacp',
              'mpls-uni', 'mpls-multi', 'jumbo', 'dot1X', 'aoe',
              'qinq', 'lldp', 'macsec', 'ecp', 'ptp', 'fcoe',
              'fcoe-init', 'qinq-old']
  pn_vnet:
    description:
      - VNET assigned to the vFlow
    required: false
    type: str
  pn_ingress_tunnel:
    description:
      - tunnel for the ingress traffic
    required: false
    type: str
  pn_id:
    description:
      - ID assigned to the vFlow
    required: false
    type: str
  pn_set_dst_port:
    description:
      - set dst port of ipv4 packets
    required: false
    type: str
  pn_action_value:
    description:
      - optional value argument between 1 and 64
    required: false
    type: str
  pn_stats_interval:
    description:
      - interval to update packet statistics for the log (in seconds)
    required: false
    type: str
  pn_precedence:
    description:
      - traffic priority value between 2 and 15
    required: false
    choices: ['default', '2 to 15']
  pn_vlan_pri:
    description:
      - priority for the VLAN - 0 to 7
    required: false
    type: str
  pn_log_stats:
    description:
      - log packet statistics for the flow
    required: false
    type: bool
  pn_udf_data2_mask:
    description:
      - mask for udf-data
    required: false
    type: str
  pn_mirror:
    description:
      - mirror configuration name
    required: false
    type: str
  pn_tos_end:
    description:
      - the ending Type of Service (ToS) number
    required: false
    type: str
  pn_src_port:
    description:
      - Layer 3 protocol source port for the vFlow
    required: false
    type: str
  pn_dscp_map:
    description:
      - DSCP map to apply on the flow. Please reapply if map
        priorities are updated
    required: false
    type: str
  pn_udf_data1_mask:
    description:
      - mask for udf-data
    required: false
    type: str
  pn_dscp_start:
    description:
      - 6-bit Differentiated Services Code Point (DSCP) start number
    required: false
    type: str
  pn_dropped:
    description:
      - match dropped or forwarded packet
    required: false
    type: bool
  pn_ttl:
    description:
      - time-to-live
    required: false
    type: str
  pn_udf_data1:
    description:
      - udf data
    required: false
    type: str
  pn_tcp_flags:
    description:
      - TCP Control Flags
    required: false
    choices: ['fin', 'syn', 'rst', 'push', 'ack', 'urg', 'ece', 'cwr']
  pn_udf_data2:
    description:
      - udf data
    required: false
    type: str
  pn_udf_data3:
    description:
      - udf data
    required: false
    type: str
  pn_log_packets:
    description:
      - log the packets in the flow
    required: false
    type: bool
  pn_dscp_end:
    description:
      - 6-bit Differentiated Services Code Point (DSCP) end number
    required: false
    type: str
  pn_action_to_ports_value:
    description:
      - action to ports value
    required: false
    type: str
  pn_src_port_mask:
    description:
      - source port mask
    required: false
    type: str
  pn_proto:
    description:
      - layer 3 protocol for the vFlow
    required: false
    choices: ['tcp', 'udp', 'icmp', 'igmp', 'ip', 'icmpv6']
  pn_tos:
    description:
      - ToS number for the vFlow.
    required: false
    type: str
  pn_vrouter_name:
    description:
      - name of the vrouter service
    required: false
    type: str
  pn_dst_mac_mask:
    description:
      - destination MAC address to use as a wildcard mask
    required: false
    type: str
  pn_set_src:
    description:
      - set src ip of ipv4 packets
    required: false
    type: str
  pn_set_src_port:
    description:
      - set src port of ipv4 packets
    required: false
    type: str
  pn_dst_ip:
    description:
      - destination IP address for the vFlow
    required: false
    type: str
  pn_cpu_class:
    description:
      - CPU class name
    required: false
    type: str
  pn_dst_ip_mask:
    description:
      - destination IP address wildcard mask for the vFlow
    required: false
    type: str
  pn_udf_name2:
    description:
      - udf name
    required: false
    type: str
  pn_flow_class:
    description:
      - vFlow class name
    required: false
    type: str
  pn_src_ip_mask:
    description:
      - source IP address wildcard mask for the vFlow
    required: false
    type: str
  pn_udf_name1:
    description:
      - udf name
    required: false
    type: str
  pn_ether_type:
    description:
      - EtherType for the vFlow
    required: false
    choices: ['ipv4', 'arp', 'wake', 'rarp', 'vlan', 'ipv6', 'lacp',
              'mpls-uni', 'mpls-multi', 'jumbo', 'dot1X', 'aoe',
              'qinq', 'lldp', 'macsec', 'ecp', 'ptp', 'fcoe',
              'fcoe-init', 'qinq-old']
  pn_enable:
    description:
      - enable or disable flows in hardware
    required: false
    type: bool
  pn_dst_port:
    description:
      - Layer 3 protocol destination port for the vFlow
    required: false
    type: str
  pn_bw_min:
    description:
      - minimum bandwidth in Gbps
    required: false
    type: str
  pn_dscp:
    description:
      - 6-bit Differentiated Services Code Point (DSCP) for the vFlow
        with range 0 to 63
    required: false
    type: str
  pn_table_name:
    description:
      - table name
    required: false
    type: str
  pn_action_set_mac_value:
    description:
      - MAC address value
    required: false
    type: str
  pn_process_mirror:
    description:
      - vFLow processes mirrored traffic or not
    required: false
    type: bool
  pn_dst_mac:
    description:
      - destination MAC address for the vFlow
    required: false
    type: str
  pn_src_mac_mask:
    description:
      - source MAC address to use as a wildcard mask
    required: false
    type: str
  pn_udf_data3_mask:
    description:
      - mask for udf-data
    required: false
    type: str
  pn_src_mac:
    description:
      - source MAC address for the vFlow
    required: false
    type: str
  pn_udf_name3:
    description:
      - udf name
    required: false
    type: str
  pn_src_ip:
    description:
      - source IP address for the vFlow
    required: false
    type: str
  pn_tos_start:
    description:
      - start Type of Service (ToS) number
    required: false
    type: str
  pn_bw_max:
    description:
      - maximum bandwidth in Gbps
    required: false
    type: str
  pn_packet_log_max:
    description:
      - maximum packet count for log rotation in the flow
    required: false
    type: str
  pn_action_to_next_hop_ip_value:
    description:
      - next-hop IP address for packet redirection
    required: false
    type: str
  pn_action:
    description:
      - forwarding action to apply to the vFlow
    required: false
    choices: ['none', 'drop', 'to-port', 'to-cpu', 'trap', 'copy-to-cpu',
              'copy-to-port', 'check', 'setvlan', 'add-outer-vlan',
              'set-tpid', 'to-port-set-vlan', 'tunnel-pkt', 'set-tunnel-id',
              'to-span', 'cpu-rx', 'cpu-rx-tx', 'set-metadata', 'set-dscp',
              'decap', 'set-dmac', 'to-next-hop-ip', 'set-dmac-to-port',
              'to-ports-and-cpu', 'set-vlan-pri', 'tcp-seq-offset',
              'tcp-ack-offset', 'l3-to-cpu-switch', 'set-smac',
              'drop-cancel-trap', 'to-ecmp-group']
  pn_burst_size:
    description:
      - Committed burst size in bytes
    required: false
  pn_in_port:
    description:
      - incoming port for the vFlow
    required: false
    type: str
  pn_set_dst:
    description:
      - set dst ip of ipv4 packets
    required: false
    type: str
  pn_dst_port_mask:
    description:
      - destination port mask
    required: false
    type: str
  pn_name:
    description:
      - name for the vFlow
    required: false
    type: str
"""

EXAMPLES = """
- name: create vflow
  pn_vflow:
    state: "present"
    pn_name: "loopback-inband-ping6"
    pn_scope: "fabric"
    pn_src_port: "36864"
    pn_src_port_mask: "0xef00"
    pn_proto: "icmpv6"
    pn_burst_size: "auto"
    pn_precedence: "15"
    pn_table_name: "System-L1-L4-Tun-1-0"
    pn_cpu_class: "icmpv6"


- name: delete vflow
  pn_vflow:
    state: "absent"
    pn_name: "loopback-inband-ping6"
    pn_id: "90006a9:38"


- name: update vflow
  pn_vflow:
    state: "update"
    pn_name: "loopback-inband-ping6"
    pn_src_port: "36864"
    pn_src_port_mask: "0xef00"
    pn_proto: "ip"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vflow command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vflow command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.netvisor.pn_netvisor import pn_cli


def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    state = module.params['state']
    command = state_map[state]

    cmd = shlex.split(cli)
    result, out, err = module.run_command(cmd)

    remove_cmd = '/usr/bin/cli --quiet -e --no-login-prompt'

    # Response in JSON format
    if result != 0:
        module.exit_json(
            command=' '.join(cmd).replace(remove_cmd, ''),
            stderr=err.strip(),
            msg="%s operation failed" % command,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cmd).replace(remove_cmd, ''),
            stdout=out.strip(),
            msg="%s operation completed" % command,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cmd).replace(remove_cmd, ''),
            msg="%s operation completed" % command,
            changed=True
        )


def check_cli(module, cli):
    """
    This method checks for idempotency using the vflow-show command.
    If a user with given name exists, return VFLOW_EXISTS as True else False.
    :param module: The Ansible module to fetch input parameters
    :param cli: The CLI string
    :return Global Booleans: VFLOW_EXISTS
    """
    # Global flags
    global VFLOW_EXISTS

    name = module.params['pn_name']

    show = cli + \
        ' vflow-show format name no-show-headers'
    show = shlex.split(show)
    out = module.run_command(show)[1]

    out = out.split()

    VFLOW_EXISTS = True if name in out else False


def main():
    """ This section is for arguments parsing """

    global state_map
    state_map = dict(
        present='vflow-create',
        absent='vflow-delete',
        update='vflow-modify'
    )

    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            state=dict(required=True, type='str',
                       choices=state_map.keys()),
            pn_vxlan_proto=dict(required=False, type='str',
                                choices=['tcp', 'udp', 'icmp',
                                         'igmp', 'ip', 'icmpv6']),
            pn_out_port=dict(required=False, type='str'),
            pn_egress_tunnel=dict(required=False, type='str'),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
            pn_dur=dict(required=False, type='str'),
            pn_vxlan=dict(required=False, type='str'),
            pn_metadata=dict(required=False, type='str'),
            pn_bd=dict(required=False, type='str'),
            pn_stp_state=dict(required=False, type='str',
                              choices=['Disabled', 'Discarding',
                                       'Learning', 'Forwarding']),
            pn_vlan=dict(required=False, type='str'),
            pn_transient=dict(required=False, type='bool'),
            pn_action_to_ecmp_group_value=dict(required=False, type='str'),
            pn_vxlan_ether_type=dict(required=False, type='str',
                                     choices=['ipv4', 'arp', 'wake', 'rarp',
                                              'vlan', 'ipv6', 'lacp',
                                              'mpls-uni', 'mpls-multi',
                                              'dot1X', 'aoe', 'qinq', 'lldp',
                                              'macsec', 'ecp', 'ptp', 'fcoe',
                                              'fcoe-init', 'qinq-old',
                                              'jumbo']),
            pn_vnet=dict(required=False, type='str'),
            pn_ingress_tunnel=dict(required=False, type='str'),
            pn_id=dict(required=False, type='str'),
            pn_set_dst_port=dict(required=False, type='str'),
            pn_action_value=dict(required=False, type='str'),
            pn_stats_interval=dict(required=False, type='str'),
            pn_precedence=dict(required=False, type='str',
                               choices=['default', '2', '3', '4', '5', '6',
                                        '7', '8', '9', '10', '11', '12',
                                        '13', '14', '15']),
            pn_vlan_pri=dict(required=False, type='str'),
            pn_log_stats=dict(required=False, type='bool'),
            pn_udf_data2_mask=dict(required=False, type='str'),
            pn_mirror=dict(required=False, type='str'),
            pn_tos_end=dict(required=False, type='str'),
            pn_src_port=dict(required=False, type='str'),
            pn_dscp_map=dict(required=False, type='str'),
            pn_udf_data1_mask=dict(required=False, type='str'),
            pn_dscp_start=dict(required=False, type='str'),
            pn_dropped=dict(required=False, type='bool'),
            pn_ttl=dict(required=False, type='str'),
            pn_udf_data1=dict(required=False, type='str'),
            pn_tcp_flags=dict(required=False, type='str',
                              choices=['fin', 'syn', 'rst', 'push',
                                       'ack', 'urg', 'ece', 'cwr']),
            pn_udf_data2=dict(required=False, type='str'),
            pn_udf_data3=dict(required=False, type='str'),
            pn_log_packets=dict(required=False, type='bool'),
            pn_dscp_end=dict(required=False, type='str'),
            pn_action_to_ports_value=dict(required=False, type='str'),
            pn_src_port_mask=dict(required=False, type='str'),
            pn_proto=dict(required=False, type='str',
                          choices=['tcp', 'udp', 'icmp',
                                   'igmp', 'ip', 'icmpv6']),
            pn_tos=dict(required=False, type='str'),
            pn_vrouter_name=dict(required=False, type='str'),
            pn_dst_mac_mask=dict(required=False, type='str'),
            pn_set_src=dict(required=False, type='str'),
            pn_set_src_port=dict(required=False, type='str'),
            pn_dst_ip=dict(required=False, type='str'),
            pn_cpu_class=dict(required=False, type='str'),
            pn_dst_ip_mask=dict(required=False, type='str'),
            pn_udf_name2=dict(required=False, type='str'),
            pn_flow_class=dict(required=False, type='str'),
            pn_src_ip_mask=dict(required=False, type='str'),
            pn_udf_name1=dict(required=False, type='str'),
            pn_ether_type=dict(required=False, type='str',
                               choices=['ipv4', 'arp', 'wake', 'rarp', 'vlan',
                                        'ipv6', 'lacp', 'mpls-uni',
                                        'mpls-multi', 'jumbo', 'dot1X', 'aoe',
                                        'qinq', 'lldp', 'macsec', 'ecp', 'ptp',
                                        'fcoe', 'fcoe-init', 'qinq-old']),
            pn_enable=dict(required=False, type='bool'),
            pn_dst_port=dict(required=False, type='str'),
            pn_bw_min=dict(required=False, type='str'),
            pn_dscp=dict(required=False, type='str'),
            pn_table_name=dict(required=False, type='str'),
            pn_action_set_mac_value=dict(required=False, type='str'),
            pn_process_mirror=dict(required=False, type='bool'),
            pn_dst_mac=dict(required=False, type='str'),
            pn_src_mac_mask=dict(required=False, type='str'),
            pn_udf_data3_mask=dict(required=False, type='str'),
            pn_src_mac=dict(required=False, type='str'),
            pn_udf_name3=dict(required=False, type='str'),
            pn_src_ip=dict(required=False, type='str'),
            pn_tos_start=dict(required=False, type='str'),
            pn_bw_max=dict(required=False, type='str'),
            pn_packet_log_max=dict(required=False, type='str'),
            pn_action_to_next_hop_ip_value=dict(required=False, type='str'),
            pn_action=dict(required=False, type='str',
                           choices=['none', 'drop', 'to-port', 'to-cpu',
                                    'trap', 'copy-to-cpu', 'copy-to-port',
                                    'check', 'setvlan', 'add-outer-vlan',
                                    'set-tpid', 'to-port-set-vlan',
                                    'tunnel-pkt', 'set-tunnel-id', 'to-span',
                                    'cpu-rx', 'cpu-rx-tx', 'set-metadata',
                                    'set-dscp', 'decap', 'set-dmac',
                                    'to-next-hop-ip', 'set-dmac-to-port',
                                    'to-ports-and-cpu', 'set-vlan-pri',
                                    'tcp-seq-offset', 'tcp-ack-offset',
                                    'l3-to-cpu-switch', 'set-smac',
                                    'drop-cancel-trap', 'to-ecmp-group']),
            pn_burst_size=dict(required=False, type='str', default='auto'),
            pn_in_port=dict(required=False, type='str'),
            pn_set_dst=dict(required=False, type='str'),
            pn_dst_port_mask=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
        ),
        required_if=(
            ['state', 'present', ['pn_name', 'pn_scope']],
            ['state', 'absent', ['pn_name', 'pn_id']],
            ['state', 'update', ['pn_name']],
        ),
        required_one_of=[['pn_vxlan_proto', 'pn_out_port',
                          'pn_egress_tunnel', 'pn_dur',
                          'pn_vxlan', 'pn_metadata',
                          'pn_bd', 'pn_stp_state',
                          'pn_vlan', 'pn_transient',
                          'pn_action_to_ecmp_group_value',
                          'pn_vxlan_ether_type',
                          'pn_vnet', 'pn_ingress_tunnel',
                          'pn_id', 'pn_set_dst_port',
                          'pn_action_value', 'pn_stats_interval',
                          'pn_precedence', 'pn_vlan_pri',
                          'pn_log_stats', 'pn_udf_data2_mask',
                          'pn_mirror', 'pn_tos_end',
                          'pn_src_port', 'pn_dscp_map',
                          'pn_udf_data1_mask', 'pn_dscp_start',
                          'pn_dropped', 'pn_ttl',
                          'pn_udf_data1', 'pn_tcp_flags',
                          'pn_udf_data2', 'pn_udf_data3',
                          'pn_log_packets', 'pn_dscp_end',
                          'pn_action_to_ports_value', 'pn_src_port_mask',
                          'pn_proto', 'pn_tos',
                          'pn_vrouter_name', 'pn_dst_mac_mask',
                          'pn_set_src', 'pn_set_src_port',
                          'pn_dst_ip', 'pn_cpu_class',
                          'pn_dst_ip_mask', 'pn_udf_name2',
                          'pn_flow_class', 'pn_src_ip_mask',
                          'pn_udf_name1', 'pn_ether_type',
                          'pn_enable', 'pn_dst_port',
                          'pn_bw_min', 'pn_bw_min',
                          'pn_dscp', 'pn_table_name',
                          'pn_action_set_mac_value', 'pn_process_mirror',
                          'pn_dst_mac', 'pn_src_mac_mask',
                          'pn_udf_data3_mask', 'pn_src_mac',
                          'pn_udf_name3', 'pn_src_ip',
                          'pn_tos_start', 'pn_bw_max',
                          'pn_packet_log_max', 'pn_action',
                          'pn_action_to_next_hop_ip_value',
                          'pn_action', 'pn_burst_size',
                          'pn_in_port', 'pn_set_dst',
                          'pn_dst_port_mask']]
    )

    # Accessing the arguments
    cliswitch = module.params['pn_cliswitch']
    state = module.params['state']
    vxlan_proto = module.params['pn_vxlan_proto']
    out_port = module.params['pn_out_port']
    egress_tunnel = module.params['pn_egress_tunnel']
    scope = module.params['pn_scope']
    dur = module.params['pn_dur']
    vxlan = module.params['pn_vxlan']
    metadata = module.params['pn_metadata']
    bd = module.params['pn_bd']
    stp_state = module.params['pn_stp_state']
    vlan = module.params['pn_vlan']
    transient = module.params['pn_transient']
    action_to_ecmp_group_value = module.params['pn_action_to_ecmp_group_value']
    vxlan_ether_type = module.params['pn_vxlan_ether_type']
    vnet = module.params['pn_vnet']
    ingress_tunnel = module.params['pn_ingress_tunnel']
    pn_id = module.params['pn_id']
    set_dst_port = module.params['pn_set_dst_port']
    action_value = module.params['pn_action_value']
    stats_interval = module.params['pn_stats_interval']
    precedence = module.params['pn_precedence']
    vlan_pri = module.params['pn_vlan_pri']
    log_stats = module.params['pn_log_stats']
    udf_data2_mask = module.params['pn_udf_data2_mask']
    mirror = module.params['pn_mirror']
    tos_end = module.params['pn_tos_end']
    src_port = module.params['pn_src_port']
    dscp_map = module.params['pn_dscp_map']
    udf_data1_mask = module.params['pn_udf_data1_mask']
    dscp_start = module.params['pn_dscp_start']
    dropped = module.params['pn_dropped']
    ttl = module.params['pn_ttl']
    udf_data1 = module.params['pn_udf_data1']
    tcp_flags = module.params['pn_tcp_flags']
    udf_data2 = module.params['pn_udf_data2']
    udf_data3 = module.params['pn_udf_data3']
    log_packets = module.params['pn_log_packets']
    dscp_end = module.params['pn_dscp_end']
    action_to_ports_value = module.params['pn_action_to_ports_value']
    src_port_mask = module.params['pn_src_port_mask']
    proto = module.params['pn_proto']
    tos = module.params['pn_tos']
    vrouter_name = module.params['pn_vrouter_name']
    dst_mac_mask = module.params['pn_dst_mac_mask']
    set_src = module.params['pn_set_src']
    set_src_port = module.params['pn_set_src_port']
    dst_ip = module.params['pn_dst_ip']
    cpu_class = module.params['pn_cpu_class']
    dst_ip_mask = module.params['pn_dst_ip_mask']
    udf_name2 = module.params['pn_udf_name2']
    flow_class = module.params['pn_flow_class']
    src_ip_mask = module.params['pn_src_ip_mask']
    udf_name1 = module.params['pn_udf_name1']
    ether_type = module.params['pn_ether_type']
    enable = module.params['pn_enable']
    dst_port = module.params['pn_dst_port']
    bw_min = module.params['pn_bw_min']
    dscp = module.params['pn_dscp']
    table_name = module.params['pn_table_name']
    action_set_mac_value = module.params['pn_action_set_mac_value']
    process_mirror = module.params['pn_process_mirror']
    dst_mac = module.params['pn_dst_mac']
    src_mac_mask = module.params['pn_src_mac_mask']
    udf_data3_mask = module.params['pn_udf_data3_mask']
    src_mac = module.params['pn_src_mac']
    udf_name3 = module.params['pn_udf_name3']
    src_ip = module.params['pn_src_ip']
    tos_start = module.params['pn_tos_start']
    bw_max = module.params['pn_bw_max']
    packet_log_max = module.params['pn_packet_log_max']
    action_to_nex_hop_ip_val = module.params['pn_action_to_next_hop_ip_value']
    action = module.params['pn_action']
    burst_size = module.params['pn_burst_size']
    in_port = module.params['pn_in_port']
    set_dst = module.params['pn_set_dst']
    dst_port_mask = module.params['pn_dst_port_mask']
    name = module.params['pn_name']

    command = state_map[state]

    # Building the CLI command string
    cli = pn_cli(module, cliswitch)

    check_cli(module, cli)
    cli += ' %s name %s ' % (command, name)

    if command == 'vflow-delete':
        if VFLOW_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vflow with name %s does not exist' % name
            )
        if pn_id:
            cli += ' id %s ' % pn_id
    else:
        if command == 'vflow-modify':
            if VFLOW_EXISTS is False:
                module.fail_json(
                     failed=True,
                     msg='vflow with name %s does not exists' % name
                )
            if pn_id:
                cli += ' id %s ' % pn_id

        if command == 'vflow-create':
            if VFLOW_EXISTS is True:
                module.exit_json(
                     skipped=True,
                     msg='vflow with name %s already exists' % name
                )
            if vnet:
                cli += ' vnet ' + vnet
            if vlan:
                cli += ' vlan ' + vlan
            if scope:
                cli += ' scope ' + scope

        if vxlan_proto:
            cli += ' vxlan-proto ' + vxlan_proto
        if out_port:
            cli += ' out-port ' + out_port
        if egress_tunnel:
            cli += ' egress-tunnel ' + egress_tunnel
        if dur:
            cli += ' dur ' + dur
        if vxlan:
            cli += ' vxlan ' + vxlan
        if metadata:
            cli += ' metadata ' + metadata
        if bd:
            cli += ' bd ' + bd
        if stp_state:
            cli += ' stp-state ' + stp_state
        if transient:
            if transient is True:
                cli += ' transient '
            else:
                cli += ' no-transient '
        if action_to_ecmp_group_value:
            cli += ' action-to-ecmp-group-value ' + action_to_ecmp_group_value
        if vxlan_ether_type:
            cli += ' vxlan-ether-type ' + vxlan_ether_type
        if ingress_tunnel:
            cli += ' ingress-tunnel ' + ingress_tunnel
        if pn_id:
            cli += ' id ' + pn_id
        if set_dst_port:
            cli += ' set-dst-port ' + set_dst_port
        if action_value:
            cli += ' action-value ' + action_value
        if stats_interval:
            cli += ' stats-interval ' + stats_interval
        if precedence:
            cli += ' precedence ' + precedence
        if vlan_pri:
            cli += ' vlan-pri ' + vlan_pri
        if log_stats:
            if log_stats is True:
                cli += ' log-stats '
            else:
                cli += ' no-log-stats '
        if udf_data2_mask:
            cli += ' udf-data2-mask ' + udf_data2_mask
        if mirror:
            cli += ' mirror ' + mirror
        if tos_end:
            cli += ' tos-end ' + tos_end
        if src_port:
            cli += ' src-port ' + src_port
        if dscp_map:
            cli += ' dscp-map ' + dscp_map
        if udf_data1_mask:
            cli += ' udf-data1-mask ' + udf_data1_mask
        if dscp_start:
            cli += ' dscp-start ' + dscp_start
        if dropped:
            if dropped is True:
                cli += ' dropped '
            else:
                cli += ' no-dropped '
        if ttl:
            cli += ' ttl ' + ttl
        if udf_data1:
            cli += ' udf-data1 ' + udf_data1
        if tcp_flags:
            cli += ' tcp-flags ' + tcp_flags
        if udf_data2:
            cli += ' udf-data2 ' + udf_data2
        if udf_data3:
            cli += ' udf-data3 ' + udf_data3
        if log_packets:
            if log_packets is True:
                cli += ' log-packets '
            else:
                cli += ' no-log-packets '
        if dscp_end:
            cli += ' dscp-end ' + dscp_end
        if action_to_ports_value:
            cli += ' action-to-ports-value ' + action_to_ports_value
        if src_port_mask:
            cli += ' src-port-mask ' + src_port_mask
        if proto:
            cli += ' proto ' + proto
        if tos:
            cli += ' tos ' + tos
        if vrouter_name:
            cli += ' vrouter-name ' + vrouter_name
        if dst_mac_mask:
            cli += ' dst-mac-mask ' + dst_mac_mask
        if set_src:
            cli += ' set-src ' + set_src
        if set_src_port:
            cli += ' set-src-port ' + set_src_port
        if dst_ip:
            cli += ' dst-ip ' + dst_ip
        if cpu_class:
            cli += ' cpu-class ' + cpu_class
        if dst_ip_mask:
            cli += ' dst-ip-mask ' + dst_ip_mask
        if udf_name2:
            cli += ' udf-name2 ' + udf_name2
        if flow_class:
            cli += ' flow-class ' + flow_class
        if src_ip_mask:
            cli += ' src-ip-mask ' + src_ip_mask
        if udf_name1:
            cli += ' udf-name1 ' + udf_name1
        if ether_type:
            cli += ' ether-type ' + ether_type
        if enable:
            if enable is True:
                cli += ' enable '
            else:
                cli += ' no-enable '
        if dst_port:
            cli += ' dst-port ' + dst_port
        if bw_min:
            cli += ' bw-min ' + bw_min
        if dscp:
            cli += ' dscp ' + dscp
        if table_name:
            cli += ' table-name ' + table_name
        if action_set_mac_value:
            cli += ' action-set-mac-value ' + action_set_mac_value
        if process_mirror:
            if process_mirror is True:
                cli += ' process-mirror '
            else:
                cli += ' no-process-mirror '
        if dst_mac:
            cli += ' dst-mac ' + dst_mac
        if src_mac_mask:
            cli += ' src-mac-mask ' + src_mac_mask
        if udf_data3_mask:
            cli += ' udf-data3-mask ' + udf_data3_mask
        if src_mac:
            cli += ' src-mac ' + src_mac
        if udf_name3:
            cli += ' udf-name3 ' + udf_name3
        if src_ip:
            cli += ' src-ip ' + src_ip
        if tos_start:
            cli += ' tos-start ' + tos_start
        if bw_max:
            cli += ' bw-max ' + bw_max
        if packet_log_max:
            cli += ' packet-log-max ' + packet_log_max
        if action_to_nex_hop_ip_val:
            cli += ' action-to-next-hop-ip-value ' + action_to_nex_hop_ip_val
        if action:
            cli += ' action ' + action
        if burst_size:
            cli += ' burst-size ' + burst_size
        if in_port:
            cli += ' in-port ' + in_port
        if set_dst:
            cli += ' set-dst ' + set_dst
        if dst_port_mask:
            cli += ' dst-port-mask ' + dst_port_mask

    run_cli(module, cli)


if __name__ == '__main__':
    main()
