#!/usr/bin/python

from __future__ import print_function
from jinja2 import Template
import subprocess
import argparse
import re

##################
# ARGUMENT PARSING
##################

parser = argparse.ArgumentParser(description='Ansible Module Generator')
parser.add_argument(
    '-c', '--cmd',
    help='command prefix',
    required=True
)
args = vars(parser.parse_args())

################

def run_cmd(cmd):
    cmd = "cli --quiet --no-login-prompt --user network-admin:test123 " + cmd
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = proc.communicate()[0]
        return output.strip().split('\n')
    except:
        print("Failed running cmd %s" % cmd)
        exit(0)

def refine(txt):
    return txt.replace('-','_')

################

SKIP_CMD = ["pager", "ping", "traceroute", "shell", "ssh", "switch",
            "switch-local", "help", "quit", "exit"]
SKIP_PATTERN = ["formatting", "one or more", "any of the", "selector",
                "following"]
ALLOWED_ACTIONS = ['set', 'create', 'add', 'modify', 'remove', 'delete']

################

simple = re.compile('^[a-zA-Z0-9-]+ [a-zA-Z0-9-]+$')
single = re.compile('^[a-zA-Z0-9-]+$')
complete_array = re.compile('^[a-zA-Z0-9-_]+ ([^|]+\|)+[^|]+$')
choice = re.compile('^([a-zA-Z0-9-]+\|)+[a-zA-Z0-9-]+$')
rangetype = re.compile('^-?\d+\.+\d+G?$')
string = re.compile('^.*string$')
number = re.compile('^.*number$')
idtype = re.compile('^.*id(ent)?(>)?$')
portlisttype = re.compile('^.*port-list$')
nidtype = re.compile('^[a-zA-Z0-9-]*id <[a-zA-Z0-9-]*id>$')
datetime = re.compile('^[a-zA-Z0-9-_]+ date/time: yyyy-mm-ddTHH:mm:ss')
duration = re.compile('^[a-zA-Z0-9-_]+ duration: #d#h#m#s')
hrtime = re.compile('^[a-zA-Z0-9-_]+ high resolution time: #ns')
mstime = re.compile('^.+\(ms\)$')
stime = re.compile('^.+\(s\)$')
name = re.compile('^.+name( \| \w+)?$')
filetype = re.compile('^.+file$')
vxlantype = re.compile('^.+vxlan$')
iptype = re.compile('^.+ ip(-| )?(address)?$')
label = re.compile('^.+label$')
desc = re.compile('^.* .* description$')
nictype = re.compile('^.+ nic$')


class ARGTYPE():
    SIMPLE="simple"
    SINGLE="single"
    ARRAY="array"
    CHOICE="choice"
    RANGE="range"

def get_arg_info(cmd, cmd_arg, arg_doc):
    raw = cmd_arg.strip("[]").strip()
    arg_str = ""
    arg_detail = []
    for skip_pattern in SKIP_PATTERN:
        if skip_pattern in raw:
            return arg_detail

    arg_detail.append(arg_doc)
    text = raw.split(" ")
    # Handle the param 'if', which cant be passed as a kwarg
    if text[0] == 'if':
        text[0] = '_if'

    if simple.match(raw) or \
       string.match(raw) or \
       number.match(raw) or \
       datetime.match(raw) or \
       duration.match(raw) or \
       hrtime.match(raw) or \
       mstime.match(raw) or \
       stime.match(raw) or \
       name.match(raw) or \
       idtype.match(raw) or \
       nidtype.match(raw) or \
       nictype.match(raw) or \
       filetype.match(raw) or \
       vxlantype.match(raw) or \
       iptype.match(raw) or \
       iptype.match(arg_doc.lower()) or \
       portlisttype.match(raw) or \
       label.match(raw) or \
       desc.match(raw):
        arg_detail.append(ARGTYPE.SIMPLE)
        arg_str = text[0]

    elif single.match(raw):
        arg_detail.append(ARGTYPE.SINGLE)
        arg_str = text[0]

    elif complete_array.match(raw):
        option = text[0]
        choices = text[1].split('|')
        arg_detail.append(ARGTYPE.ARRAY)
        arg_str = text[0]
        arg_detail.append(choices)

    elif choice.match(raw):
        options = raw.split('|')
        arg_detail.append(ARGTYPE.CHOICE)
        arg_str = options[0]
        arg_detail.append(options)

    elif rangetype.match(text[1]):
        start = text[1].split('.')[0]
        end = text[1].split('.')[-1]
        if not end[-1].isdigit():
            end = end[:-1]
        arg_detail.append(ARGTYPE.RANGE)
        arg_str = text[0]
        arg_detail.append((start, end))

    else:
        print("Unhandled cmd: %s <<%s>>" % (cmd, raw))
        exit(1)

    return arg_str, arg_detail

################

ansible_template = Template(open("pn_module_template.j2", "r").read())

cmd_indicator = re.compile('^\w')
arg_indicator = re.compile('^\s[a-zA-Z\[]')
cmd_doc = {}
all_cmds = [args["cmd"]]
for cli_cmd in all_cmds:
    p_cmd = re.split(r'\s+', cli_cmd)
    cmd_prefix = p_cmd[0]
    cmd_info = run_cmd("help %s" % cmd_prefix)
    cmd, cmd_action = None, None
    skip = False
    for ilen in range(len(cmd_info)):
        info = cmd_info[ilen].rstrip()
        temp = re.split(r'\s+', info)
        cmd_arg, cmd_help = temp[0].strip(), " ".join(temp[1:])
        if cmd_indicator.match(info):
            main_cmd = cmd_arg
            temp = cmd_arg.split('-')
            cmd, cmd_action = '-'.join(temp[:-1]), temp[-1]
            if cmd not in all_cmds \
              or cmd_arg in SKIP_CMD \
              or cmd_action not in ALLOWED_ACTIONS:
                skip = True
                continue
            skip = False
            print("%s => %s" % (cmd, cmd_action))
            if not cmd_doc.get(cmd, False):
                cmd_doc[cmd] = {"args": {}, "actions": {}}
            temp = info.split(" ")
            doc_len = len(temp[0]) - 7
            for i in info[len(temp[0]):]:
                if i != ' ':
                    break
                doc_len += 1
            cmd_doc[cmd]["actions"][cmd_action] = cmd_help
        elif arg_indicator.match(info) and not skip:
            if not cmd and not cmd_action:
                print("Error for: \"%s\"" % main_cmd)
                exit(1)
            arg = info[1:doc_len].strip()
            arg_doc = info[doc_len:].strip()
            if arg == "[ switch switch-name ]" and not arg_doc:
                arg_doc = "switch name"
            elif not arg_doc:
                incr = 1
                arg_str = arg
                new_dl = doc_len - 9
                while (ilen + incr) < len(cmd_info):
                    future = cmd_info[ilen + incr].strip()
                    f_arg = future[:new_dl].strip()
                    f_arg_doc = future[new_dl:].strip()
                    arg_str += f_arg
                    if f_arg_doc:
                        arg = arg_str
                        arg_doc = f_arg_doc
                        break
                    incr += 1
            arg_str, arg_details = get_arg_info(cmd, arg, arg_doc)
            if not arg_details:
                continue
            # Argument compaction
            nkey = tuple([cmd_action])
            new_args = cmd_doc[cmd]['args']
            for e_act in new_args:
                if arg_str in new_args[e_act]:
                    nkey = tuple(sorted(set(tuple([cmd_action]) + e_act)))
                    new_args[e_act].pop(arg_str)
                    if not new_args[e_act]:
                        new_args.pop(e_act)
                    break
            if new_args.get(nkey, None):
                new_args[nkey][arg_str] = arg_details
            else:
                new_args[nkey] = {arg_str: arg_details}
        else:
            continue
    if cli_cmd not in cmd_doc:
        print("Invalid cmd prefix: %s" % cli_cmd)
        exit(1)
    mod_name = "pn_%s.py" % refine(cli_cmd)
    with open(mod_name, "w") as fh:
        fh.write(ansible_template.render(cmd=cli_cmd, cmd_dict=cmd_doc[cli_cmd]))
        print("Module generated: %s" % mod_name)

# TODO Cleanup of below code
#
#with open('pn_ansible_lib.py', 'r') as FILE:
#    PRE_DATA = FILE.read()
#
#pn_cli_lib = open("pn_cli.py", "w")
#
#def struct_simple(option):
#    return """        if '%s' in kwargs:
#            command += \" %s %%s\" %% kwargs['%s']""" % (
#               refine(option), option, refine(option))
#
#def struct_single(option):
#    return """        if '%s' in kwargs:
#            command += \" %s\"""" % (refine(option), option)
#
#def struct_array(option, choices):
#    return """        if '%s' in kwargs:
#            if kwargs['%s'] in %s:
#                command += \" %s %%s\" %% kwargs['%s']
#            else:
#                print(\"Incorrect argument: %%s\") %% kwargs['%s']""" % (
#                    refine(option), refine(option), choices, option,
#                    refine(option), refine(option))
#
#def struct_choice(choices):
#    return """        if '%s' in kwargs:
#            if kwargs['%s']:
#                command += \" %s\"
#            else:
#                command += \" %s\"""" % (
#                    refine(choices[0]), refine(choices[0]), choices[0],
#                    choices[1])
#
#def struct_range(option, start, end):
#    return """        if '%s' in kwargs:
#            if kwargs['%s'] in range(%d, %d):
#                command += \" %s %%s\" %% kwargs['%s']
#           """ % (refine(option), refine(option), int(start), int(end)+1,
#                  option, refine(option))
#
#pn_cli_lib.write(PRE_DATA)
#
#for cmd_prefix in sorted(cmd_doc, key = lambda x: (x.split('-')[:-1],len(x))):
#    for cmd_action in cmd_doc[cmd_prefix]:
#        cmd = cmd_prefix + '-' + cmd_action
#        refined_cmd = refine(cmd)
#        pn_cli_lib.write("""
#    def %s(self, **kwargs):
#        command = '%s'\n""" % (refined_cmd, cmd))
#        #if cmd not in CMD_FILTER:
#        #    continue
#        if "show" == cmd.split('-')[-1]:
#            continue
#        for cmd_arg in cmd_doc[cmd_prefix][cmd_action]['args']:
#            raw = cmd_arg[0].strip("[]").strip()
#            text = raw.split(" ")
#            if show.match(refined_cmd) or status.match(refined_cmd):
#                if text[0] == "formatting":
#                    break
#    
#            # Ignore unnecessary things
#            if text[0:3] == "one or more".split(" "):
#                continue
#            elif text[0:3] == "at least 1".split(" "):
#                continue
#            elif text[0:3] == "any of the".split(" "):
#                continue
#            elif refine(text[0]) == refined_cmd:
#                continue
#            elif "selector" in raw:
#                continue
#            elif "following" in raw:
#                continue
#            elif "formatting" in raw:
#                continue
#            elif "pager" == cmd:
#                continue
#            elif "vrouter-vtysh-cmd" == cmd:
#                continue
#    
#            # Handle the param 'if', which cant be passed as a kwarg
#            if text[0] == 'if':
#                text[0] = '_if'
#    
#            if simple.match(raw) or \
#               datetime.match(raw) or \
#               duration.match(raw) or \
#               hrtime.match(raw) or \
#               mstime.match(raw) or \
#               stime.match(raw) or \
#               name.match(raw) or \
#               idtype.match(raw) or \
#               nidtype.match(raw) or \
#               nictype.match(raw) or \
#               filetype.match(raw) or \
#               vxlantype.match(raw) or \
#               iptype.match(raw) or \
#               label.match(raw) or \
#               desc.match(raw):
#                pn_cli_lib.write(struct_simple(text[0]) + '\n')
#    
#            elif single.match(raw):
#                pn_cli_lib.write(struct_single(text[0]) + '\n')
#    
#            elif complete_array.match(raw):
#                option = text[0]
#                choices = text[1].split('|')
#                pn_cli_lib.write(struct_array(option, choices) + '\n')
#    
#            elif choice.match(raw):
#                options = raw.split('|')
#                pn_cli_lib.write(struct_choice(options) + '\n')
#    
#            elif rangetype.match(text[1]):
#                start = text[1].split('.')[0]
#                end = text[1].split('.')[-1]
#                if not end[-1].isdigit():
#                    end = end[:-1]
#                pn_cli_lib.write(struct_range(text[0], start, end) + '\n')
#    
#            else:
#                print("Unhandled cmd: %s >>%s<<" % (refined_cmd, raw))
#
#        if show.match(refined_cmd):
#            pn_cli_lib.write(" "*8 + "command = self.add_common_args(command, \
#kwargs)\n")
#
#        pn_cli_lib.write("""
#        return self.send_command(command)
#""")
