# Ansible Automation Framework
## Automation framework to install the Sysdig agent on:
- Kubernetes (Vanilla or OCP) 
- docker container on Linux 
- systemd daemon on Linux

## Pre-reqs

Ubuntu 16.04 and 18.04
Run:
`$ apt update -y` - Run `apt upgrade` - Reboot

Install python3.8: 

`$ apt-get install python3.8`  (FYI - Python3.6 is installed on Ubuntu 18.04 by default).

Make sure Python3.8 is the default by doing the following:

------------------------------------------------

`$ python3 --version`

Python 3.6.9

`$ python3.8 --version`

Python 3.8.0

`$ update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 1`

`$ update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 2`

`$ python3 --version`

Python 3.8.0

------------------------------------------------
Validated python3 version stated above:

`$ python3 -V = 3.8.0`

Then install pip using:

`$ apt-get install python3-pip`

`$ pip3 -V` = 9.0.1

`$ pip3 install openshift`

`$ pip3 install ansible` 

`$ apt-get install software-properties-common`

`$ apt-add-repository --yes --update ppa:ansible/ansible`

`$ apt-get update`

`$ apt-get install ansible`

`$ ansible-galaxy collection install community.kubernetes`

## Commands to execute playbook:
NOTE: For TAGS systemd-install and docker-install, make sure there is proper access for the ansible user to connect to the hosts in the hosts.ini file using a private/public key pair, and the ansible user has sudo with NO password on each host.
- Be sure to put the following line in the sudoers file:
  
  ansible ALL=(ALL) NOPASSWD: ALL
- Put the PRIVATE IP's of the hosts into the `hosts.ini` file.  Examples are provided in the exisiting hosts.ini file.

Make sure your ansible user has the proper kubeconfig file to access your kubernetes cluster with kubectl admin access.

Make sure all of the variables are filled in properly for your Sysdig backend connection in `group_vars/agent_vars.yaml` .

 _Use Ansible vault to store your SysDig Agent access key._
You can edit the exisitng vaultfile.yaml using:

`ansible~$: ansible-vault edit agent/vaultfile.yaml`

The command will ask you for a password (use Passw0rd).

or....

you can create a new vaultfile.yaml with the:

`ansible~$: ansible-vault create agent/vaultfile.yaml`

This command will ask you to create a new password.

Then it opens a vim editor.

Add the following line, but use your Sysdig Agent Key.

`sysdig_access_key: XXXXXX-YOUR-AGENT-KEY-XXXXXX`

`ansible~$: cd agent`

`ansible~$:  ansible-playbook sysdig_agent_install.yml --vault-id @prompt -e @vaultfile.yaml -e @group_vars/agent_vars.yaml --tag k8s-install`


## Requirements
- ssh
- Ansible 2.6+
- SysDig account access key
- Ansible Vault to store SysDig access key

### See (group_vars/agent_vars.yaml).

Make sure all of the variables are filled in properly for your Sysdig backend connection.

## Supported Deployments
- k8s
- docker
- linux

## Playbook Execution
Run this command from the agent directory to install the agent on a k8s cluster. 

`ansible~$:  ansible-playbook sysdig_agent_install.yml --vault-id @prompt -e @vaultfile.yaml -e @group_vars/agent_vars.yaml --tag k8s-install`

It will ask you to enter vault password. Please enter the one used when crearing the vaultfile.yaml above.

- -i hosts: Inventory file is provided
- --vault-id @prompt: will prompt for vaultfile password
- -e @vaultfile.yaml: Agent access key
- -e @group_vars/agent_vars.yaml: agent config file
- --tag k8s-install: tag for installing agent as a daemonset on a k8s cluster

## Controlled Execution
Use of Tags
If you want to execute specific section of framework, ansible tags can be used.

### Tag Name	Description
- k8s-install	 -- perform agent install on k8s cluster as a daemonset
- docker-install  -- perform agent install using docker
- systemd-install -- perform agent install using systemctl deamon

### Example: 
`ansible-playbook sysdig_agent_install.yml --vault-id @prompt -e @vaultfile.yaml -e @group_vars/agent_vars.yaml --tag k8s-install`

`ansible-playbook sysdig_agent_install.yml -b --vault-id @prompt -e @vaultfile.yaml -e @group_vars/agent_vars.yaml --tag docker-install --private-key /home/ansible/.ssh/id_rsa`

`ansible-playbook sysdig_agent_install.yml -b --vault-id @prompt -e @vaultfile.yaml -e @group_vars/agent_vars.yaml --tag systemd-install --private-key /home/ansible/.ssh/id_rsa`

