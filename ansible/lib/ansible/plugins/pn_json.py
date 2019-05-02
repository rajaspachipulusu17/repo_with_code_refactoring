# (c) 2016, Matt Martz <matt@sivel.net>
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
from ansible.plugins.callback import CallbackBase
import json

__metaclass__ = type


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'pn_json'

    def __init__(self, display=None):
        super(CallbackModule, self).__init__(display)
        # It is initialised at the start of the playbook
        self.results = []

    def _new_play(self, play):
        return {
            'play': {
                'name': play.name,
                'id': str(play._uuid)
            },
            'tasks': [],
        }

    def _new_task(self, task):
        return {
            'task': {
                'name': task.name,
                'id': str(task._uuid)
            },
            'hosts': {},
            'status': {}
        }

    def v2_playbook_on_play_start(self, play):
        # This part is only at the start of the play.
        # So, in between tasks, this part doesn't comes into picture.
        self.results = []
        self.results.append(self._new_play(play))

    def v2_playbook_on_task_start(self, task, is_conditional):
        self.results[-1]['tasks'] = []
        self.results[-1]['tasks'].append(self._new_task(task))

    def v2_runner_on_ok(self, result, **kwargs):
        host = result._host
        if 'task' not in result._result.keys():
            result._result['task'] = ''
        if 'summary' not in result._result.keys():
            result._result['summary'] = ''
        if 'msg' not in result._result.keys():
            result._result['msg'] = ''
        if 'failed' not in result._result.keys():
            result._result['failed'] = ''
        if 'exception' not in result._result.keys():
            result._result['exception'] = ''
        if 'unreachable' not in result._result.keys():
            result._result['unreachable'] = ''
        self.results[-1]['tasks'][-1]['hosts'][host.name] = result._result

        if result._result['unreachable'] == True or result._result[
            'failed'] == True:
            self.results[-1]['tasks'][-1]['status'] = '1'
        elif result._result['failed'] == False:
            self.results[-1]['tasks'][-1]['status'] = '0'
        else:
            self.results[-1]['tasks'][-1]['status'] = '-1'

        output = {
            'plays': self.results,
        }

        if self.results[-1]['tasks'][-1]['status'] != "-1":
            print('__________ANSIBLE_TASK_BOUNDARY_STARTS__________')
            print(json.dumps(output, indent=4, sort_keys=True))
            print('__________ANSIBLE_TASK_BOUNDARY_ENDS__________')

    def v2_playbook_on_stats(self, stats):
        """Display info about playbook statistics"""

        hosts = sorted(stats.processed.keys())

        summary = {}
        for h in hosts:
            s = stats.summarize(h)
            summary[h] = s

        output = {
            'stats': summary
        }

        print(json.dumps(output, indent=4, sort_keys=True))

    v2_runner_on_failed = v2_runner_on_ok
    v2_runner_on_unreachable = v2_runner_on_ok
    v2_runner_on_skipped = v2_runner_on_ok
