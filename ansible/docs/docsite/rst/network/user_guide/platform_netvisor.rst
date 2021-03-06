.. _netvisor_platform_options:

**********************************
Pluribus NETVISOR Platform Options
**********************************

Pluribus NETVISOR Ansible modules only support CLI connections today. ``httpapi`` modules may be added in future.
This page offers details on how to use ``network_cli`` on NETVISOR in Ansible.

Pluribus NETVISOR Ansible modules are supported from Ansible version 2.8. Once Ansible 2.8 is installed you can follow
the below document and use Pluribus NETVISOR modules.

.. contents:: Topics

Connections Available
================================================================================

+---------------------------+-----------------------------------------------+
|..                         | CLI                                           |
+===========================+===============================================+
| **Protocol**              |  SSH                                          |
+---------------------------+-----------------------------------------------+
| | **Credentials**         | | uses SSH keys / SSH-agent if present        |
| |                         | | accepts ``-u myuser -k`` if using password  |
+---------------------------+-----------------------------------------------+
| **Indirect Access**       | via a bastion (jump host)                     |
+---------------------------+-----------------------------------------------+
| | **Connection Settings** | | ``ansible_connection: network_cli``         |
| |                         | |                                             |
| |                         | |                                             |
| |                         | |                                             |
| |                         | |                                             |
+---------------------------+-----------------------------------------------+
| | **Enable Mode**         | | not supported by NETVISOR                   |
| | (Privilege Escalation)  | |                                             |
+---------------------------+-----------------------------------------------+
| **Returned Data Format**  | ``stdout[0].``                                |
+---------------------------+-----------------------------------------------+

Pluribus NETVISOR does not support ``ansible_connection: local``. You must use ``ansible_connection: network_cli``.

Using CLI in Ansible
====================

Example CLI ``group_vars/netvisor.yml``
---------------------------------------

.. code-block:: yaml

   ansible_connection: network_cli
   ansible_network_os: netvisor
   ansible_user: myuser
   ansible_password: !vault...
   ansible_ssh_common_args: '-o ProxyCommand="ssh -W %h:%p -q bastion01"'


- If you are using SSH keys (including an ssh-agent) you can remove the ``ansible_password`` configuration.
- If you are accessing your host directly (not through a bastion/jump host) you can remove the ``ansible_ssh_common_args`` configuration.
- If you are accessing your host through a bastion/jump host, you cannot include your SSH password in the ``ProxyCommand`` directive. To prevent secrets from leaking out (for example in ``ps`` output), SSH does not support providing passwords via environment variables.

Example CLI Task
----------------

.. code-block:: yaml

   - name: Create access list
     pn_access_list:
       pn_name: "foo"
       pn_scope: "local"
       state: "present"
     register: acc_list
     when: ansible_network_os == 'netvisor'


.. include:: shared_snippets/SSH_warning.txt
