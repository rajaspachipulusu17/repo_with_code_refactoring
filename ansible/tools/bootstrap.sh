#!/usr/bin/env bash

PRG="$0"
PRGDIR=`dirname "$PRG"`
ERR_PLAYBOOK_EXEC=1

#ping default gateway to workaround the connectivity issue
#figure out the issue. somehow arp optimizatin is enabled on the tme TOR and this block ARP to reach phi. This step probably can be skipped in the future
ping -c 5 $(/sbin/ip route | awk '/default/ { print $3 }')

# install ansible and other required packages
apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    && apt-get clean

apt-get update && apt-get install -y \
    sudo \
    && apt-get clean
apt-get install nfs-common -y
apt-get install git  sshpass -y
apt-get install python-pip -y

pip install --upgrade pip
python -m pip install ansible==${ANSIBLE_VERSION:-2.3.0.0}

python -m pip install paramiko==${PARAMIKO_VERSION:-1.16.0}
git clone https://$GIT_USER:$GIT_PASS@github.com/PluribusTME/pluribus-ansible.git -b $BRANCH_NAME

cp -Rf pluribus-ansible/  /opt/
sudo mkdir -p /etc/ansible/
sudo cp /opt/pluribus-ansible/ansible/examples/ansible.cfg /etc/ansible/
ln -s /opt/pluribus-ansible/ansible/plugins/pn_json.py /usr/local/lib/python2.7/dist-packages/ansible/plugins/callback/pn_json.py && \
ln -s /opt/pluribus-ansible/ansible/plugins/pn_paramiko.py /usr/local/lib/python2.7/dist-packages/ansible/plugins/connection/pn_paramiko.py && \
ln -s /opt/pluribus-ansible/ansible/module_utils/pn_nvos.py  /usr/local/lib/python2.7/dist-packages/ansible/module_utils/pn_nvos.py


cd /opt/pluribus-ansible/ansible/playbooks/ && ansible-playbook pn_test_ansible.yml  -vvvv
if [[ $? -ne 0 ]] ; then
     echo 'Ansible module path is incorrect'
     exit $ERR_PLAYBOOK_EXEC
fi
exit 0
