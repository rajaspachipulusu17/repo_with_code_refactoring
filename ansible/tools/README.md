# Ansible Module Generator

Script to auto-generate Ansible modules for Netvisor CLI commands

#### Dependencies
 - Requires jinja2 module: `pip install jinja2`

#### Command usage:
```
# python code_generator.py
usage: code_generator.py [-h] -c CMD
code_generator.py: error: argument -c/--cmd is required
```

#### How to run:
```
# python  code_generator.py -c vrouter-prefix-list
vrouter-prefix-list => add
vrouter-prefix-list => add
vrouter-prefix-list => add
vrouter-prefix-list => modify
vrouter-prefix-list => remove
Module generated: pn_vrouter_prefix_list.py
```
