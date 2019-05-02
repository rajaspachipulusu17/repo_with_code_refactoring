#!/usr/bin/python
""" PN CLI sys-flow-setting-modify """
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
module: pn_sys_flow_setting
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify sys-flow-setting.
description:
  - C(modify): update a system flow setting
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
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - sys-flow-setting configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_arp:
    description:
      - ARP learning
    required: false
    type: bool
  pn_control:
    description:
      - control
    required: false
    type: bool
  pn_tpm_enable:
    description:
      - Enable Trusted Platform Module support
    required: false
    type: bool
  pn_vflow_conflict_check:
    description:
      - enable/disable vflow conflict checking
    required: false
    type: bool
  pn_encap_cpu_tx_to_pn:
    description:
      - encap data packets sent to neighboring PN switch
    required: false
    type: bool
  pn_nvos_reboot:
    description:
      - reboots nvosd.
    required: false
    type: bool
  pn_cluster_analytics_flag:
    description:
      - flag for activating analytics on the switch
    required: false
    type: bool
  pn_encap_cpu_cluster_tx:
    description:
      - encap cluster data packets sent cluster peer
    required: false
    type: bool
  pn_hog_drain_time:
    description:
      - time spent draining cpu class
    required: false
    type: str
  pn_vlag_cluster_comm_timeout:
    description:
      - VLAG cluster communication timeout (microseconds)
    required: false
    type: str
  pn_ipv6_raguard_max_vlans:
    description:
      - Maximum number of vlans that can be attached to RA Guard policies
    required: false
    type: str
  pn_nd_learning:
    description:
      - IPv6 ND Advt learning
    required: false
    type: bool
  pn_num_ipv6_128b_entries:
    description:
      - Number of IPv6 routes with mask > 64
    required: false
    type: str
  pn_hog_drain_rate:
    description:
      - rate-limit set when draining cpu class
    required: false
    type: str
  pn_loopback_process_cpu_packets:
    description:
      - enable/disable processing of cpu packets from loopback ports
    required: false
    type: bool
  pn_cluster_control_flow:
    description:
      - enable cluster control flow
    required: false
    type: bool
  pn_unified_forwarding_table_mode:
    description:
      - L2/L3 unified forwarding table size mode
    required: false
    choices: ['mode0-max-L2', 'mode1-L2+', 'mode2-L3+', 'mode3-max-L3', 'mode4-max-LPM']
  pn_cpu_rx_rate_pps:
    description:
      - pci-e rx rate limit (packet per second)
    required: false
    type: str
  pn_vxlan_tunnel_timeout:
    description:
      - enable VXLAN tunnel timeout
    required: false
    type: bool
  pn_manage_mac_table:
    description:
      - enable MAC table management
    required: false
    type: bool
  pn_owner_fabric_l2_retire:
    description:
      - enable fabric-wide L2 retire (flush) if vport owner changes
    required: false
    type: bool
  pn_fabric_comm_analytics:
    description:
      - enable Fabric communication analytics
    required: false
    type: bool
  pn_auto_reboot_timeout:
    description:
      - timeout for auto-reboot if the switch is non-responsive
    required: false
    type: str
  pn_auto_vlag:
    description:
      - enable auto vlag
    required: false
    type: bool
  pn_route_entries:
    description:
      - number of route entries - 0 to 60000
    required: false
    type: str
"""

EXAMPLES = """
- name: System flow setting
  pn_sys_flow_setting:
    pn_cliswitch: "{{ inventory_hostname }}"
    pn_action: "modify"
    pn_nvos_reboot: False
    pn_num_ipv6_128b_entries: "256"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the sys-flow-setting command.
  returned: always
  type: list
stderr:
  description: set of error responses from the sys-flow-setting command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

RESTART_STR = 'Modified settings require a REBOOT to take effect'

def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    action = module.params['pn_action']
    reboot = module.params['pn_nvos_reboot']
    switch = module.params['pn_cliswitch']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="sys-flow-setting %s operation failed" % action,
            changed=False
        )

    if out and RESTART_STR in out and reboot == True:
        cli = pn_cli(module, switch, username, password)
        cli += ' nvos-restart '
        out = run_cli(module, cli)
        if out is not None:
            out += out
            module.exit_json(
                command=cli,
                stdout=out.strip(),
                msg="system-settings %s operation completed " % action,
                changed=True
            )
    else:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="sys-flow-setting %s operation completed " % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_arp=dict(required=False, type='bool'),
            pn_nvos_reboot=dict(required=False, type='bool'),
            pn_control=dict(required=False, type='bool'),
            pn_tpm_enable=dict(required=False, type='bool'),
            pn_vflow_conflict_check=dict(required=False, type='bool'),
            pn_encap_cpu_tx_to_pn=dict(required=False, type='bool'),
            pn_cluster_analytics_flag=dict(required=False, type='bool'),
            pn_encap_cpu_cluster_tx=dict(required=False, type='bool'),
            pn_hog_drain_time=dict(required=False, type='str'),
            pn_vlag_cluster_comm_timeout=dict(required=False, type='str'),
            pn_ipv6_raguard_max_vlans=dict(required=False, type='str'),
            pn_nd_learning=dict(required=False, type='bool'),
            pn_num_ipv6_128b_entries=dict(required=False, type='str'),
            pn_hog_drain_rate=dict(required=False, type='str'),
            pn_loopback_process_cpu_packets=dict(required=False, type='bool'),
            pn_cluster_control_flow=dict(required=False, type='bool'),
            pn_unified_forwarding_table_mode=dict(required=False, type='str',
                                                  choices=['mode0-max-L2',
                                                           'mode1-L2+', 'mode2-L3+',
                                                           'mode3-max-L3',
                                                           'mode4-max-LPM']),
            pn_cpu_rx_rate_pps=dict(required=False, type='str'),
            pn_vxlan_tunnel_timeout=dict(required=False, type='bool'),
            pn_manage_mac_table=dict(required=False, type='bool'),
            pn_owner_fabric_l2_retire=dict(required=False, type='bool'),
            pn_fabric_comm_analytics=dict(required=False, type='bool'),
            pn_auto_reboot_timeout=dict(required=False, type='str'),
            pn_auto_vlag=dict(required=False, type='bool'),
            pn_route_entries=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    arp = module.params['pn_arp']
    nvos_reboot = module.params['pn_nvos_reboot']
    control = module.params['pn_control']
    tpm_enable = module.params['pn_tpm_enable']
    vflow_conflict_check = module.params['pn_vflow_conflict_check']
    encap_cpu_tx_to_pn = module.params['pn_encap_cpu_tx_to_pn']
    cluster_analytics_flag = module.params['pn_cluster_analytics_flag']
    encap_cpu_cluster_tx = module.params['pn_encap_cpu_cluster_tx']
    hog_drain_time = module.params['pn_hog_drain_time']
    vlag_cluster_comm_timeout = module.params['pn_vlag_cluster_comm_timeout']
    ipv6_raguard_max_vlans = module.params['pn_ipv6_raguard_max_vlans']
    nd_learning = module.params['pn_nd_learning']
    num_ipv6_128b_entries = module.params['pn_num_ipv6_128b_entries']
    hog_drain_rate = module.params['pn_hog_drain_rate']
    loopback_process_cpu_packets = module.params['pn_loopback_process_cpu_packets']
    cluster_control_flow = module.params['pn_cluster_control_flow']
    unified_forwarding_table_mode = module.params['pn_unified_forwarding_table_mode']
    cpu_rx_rate_pps = module.params['pn_cpu_rx_rate_pps']
    vxlan_tunnel_timeout = module.params['pn_vxlan_tunnel_timeout']
    manage_mac_table = module.params['pn_manage_mac_table']
    owner_fabric_l2_retire = module.params['pn_owner_fabric_l2_retire']
    fabric_comm_analytics = module.params['pn_fabric_comm_analytics']
    auto_reboot_timeout = module.params['pn_auto_reboot_timeout']
    auto_vlag = module.params['pn_auto_vlag']
    route_entries = module.params['pn_route_entries']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'sys-flow-setting-' + mod_action
    if mod_action in ['modify']:
        if arp:
            if arp is True:
                cli += ' arp '
            else:
                cli += ' no-arp '
        if control:
            if control is True:
                cli += ' control '
            else:
                cli += ' no-control '
        if tpm_enable:
            if tpm_enable is True:
                cli += ' tpm-enable '
            else:
                cli += ' no-tpm-enable '
        if vflow_conflict_check:
            if vflow_conflict_check is True:
                cli += ' vflow-conflict-check '
            else:
                cli += ' no-vflow-conflict-check '
        if encap_cpu_tx_to_pn:
            if encap_cpu_tx_to_pn is True:
                cli += ' encap-cpu-tx-to-pn '
            else:
                cli += ' no-encap-cpu-tx-to-pn '
        if cluster_analytics_flag:
            if cluster_analytics_flag is True:
                cli += ' cluster-analytics-flag '
            else:
                cli += ' no-cluster-analytics-flag '
        if encap_cpu_cluster_tx:
            if encap_cpu_cluster_tx is True:
                cli += ' encap-cpu-cluster-tx '
            else:
                cli += ' no-encap-cpu-cluster-tx '
        if hog_drain_time:
            cli += ' hog-drain-time ' + hog_drain_time
        if vlag_cluster_comm_timeout:
            cli += ' vlag-cluster-comm-timeout ' + vlag_cluster_comm_timeout
        if ipv6_raguard_max_vlans:
            cli += ' ipv6-raguard-max-vlans ' + ipv6_raguard_max_vlans
        if nd_learning:
            if nd_learning is True:
                cli += ' nd-learning '
            else:
                cli += ' no-nd-learning '
        if num_ipv6_128b_entries:
            cli += ' num-ipv6-128b-entries ' + num_ipv6_128b_entries
        if hog_drain_rate:
            cli += ' hog-drain-rate ' + hog_drain_rate
        if loopback_process_cpu_packets:
            if loopback_process_cpu_packets is True:
                cli += ' loopback-process-cpu-packets '
            else:
                cli += ' no-loopback-process-cpu-packets '
        if cluster_control_flow:
            if cluster_control_flow is True:
                cli += ' cluster-control-flow '
            else:
                cli += ' no-cluster-control-flow '
        if unified_forwarding_table_mode:
            cli += ' unified-forwarding-table-mode ' + unified_forwarding_table_mode
        if cpu_rx_rate_pps:
            cli += ' cpu-rx-rate-pps ' + cpu_rx_rate_pps
        if vxlan_tunnel_timeout:
            if vxlan_tunnel_timeout is True:
                cli += ' vxlan-tunnel-timeout '
            else:
                cli += ' no-vxlan-tunnel-timeout '
        if manage_mac_table:
            if manage_mac_table is True:
                cli += ' manage-mac-table '
            else:
                cli += ' no-manage-mac-table '
        if owner_fabric_l2_retire:
            if owner_fabric_l2_retire is True:
                cli += ' owner-fabric-l2-retire '
            else:
                cli += ' no-owner-fabric-l2-retire '
        if fabric_comm_analytics:
            if fabric_comm_analytics is True:
                cli += ' fabric-comm-analytics '
            else:
                cli += ' no-fabric-comm-analytics '
        if auto_reboot_timeout:
            cli += ' auto-reboot-timeout ' + auto_reboot_timeout
        if auto_vlag:
            if auto_vlag is True:
                cli += ' auto-vlag '
            else:
                cli += ' no-auto-vlag '
        if route_entries:
            cli += ' route-entries ' + route_entries

    run_cli(module, cli)

if __name__ == '__main__':
    main()
