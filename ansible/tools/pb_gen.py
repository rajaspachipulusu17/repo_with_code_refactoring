#!/usr/bin/python

import argparse
import os
import re

def main():

    parser = argparse.ArgumentParser(description='Generate playbook template using module')
    parser.add_argument(
        "-m", "--module",
        help='Specify the module name',
        required=True
    )

    parser.add_argument(
        '-p', '--playbook',
        help='Give a name (sample.yml) to save playbook as',
        required=False,
    )

    args = vars(parser.parse_args())

    if args['playbook']:
        playbook_name = args['playbook']
    else:
        playbook_name = args['module'][3:] + ".yml"
    module_name = args['module']

    module_path = os.popen('ansible --version | grep "configured module search path"').read()
    module_path = module_path.split("[u'")[1]
    module_path = module_path.split("']")[0]
    module_path += '/' + module_name + '.py'

    if not os.path.exists(module_path):
        print("Invalid module name/path: " + module_path)
        print("Please verify and give the correct name/path")
        exit(0)
    else:
        module_file = os.path.basename(module_path)
        entity = module_name.split('pn_')[1]
        entity = entity.replace('_', '-')
        print("Generating playbook template for: " + module_name)

    pretext = """# This Playbook is for configuring %s.
# It uses the %s module.
# Fill-in the values for the labels and comment the labels that
# are not required.
---
- name: "Configure %s"
  hosts:
  tags:

  tasks:
    - name: "Configure %s"
      %s:
        state:
""" % (entity, module_file, entity, entity, module_name)

    posttext = """      register: output
    - debug:
        var: output
"""
    with open(playbook_name, "w+") as fd:
        fd.write(pretext)
    fd.close()
    keys = []
    module = open(module_path, "r")
    for line in module.readlines():
        if re.search('pn_', line):
            if line.__contains__('=dict('):
                line = line.strip()
                keys.append(line.split('=')[0] + ':')
    module.close()

    with open(playbook_name, "a+") as fd:
        for index in range(0, len(keys)):
            fd.write("        " + keys[index] + "\n")
        fd.write(posttext)
    fd.close()
    print("Generated playbook template=> %s" % playbook_name)

if __name__ == '__main__':
    main()
