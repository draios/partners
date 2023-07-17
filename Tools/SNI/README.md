# single-node-installer

## About

This is to be used for POV installs by the Sysdig Professional Services Team.  This will install and setup Kubernetes
on a server allowing the Sysdig on-premise backend to be installed (monitor/secure/agent)

## Requirements

* 1 Server with Internet Connectivity (to install system packages required to run K8s and the Sysdig)
* Minimum 16 CPU / 64GB RAM
* OS (Debian 9/10/11, CentOS 7/8/9, RHEL 7/8/9, Ubuntu 18/20/22)  
  **NOTE: CentOS Stream 9 kernel 5.14.0-282.el9.x86_64 is not supported**
* installer-5.1.8-1 in /usr/bin/installer

## Install Notes

* CentOS 7, Debian 9/10, RHEL 7 and Ubuntu 18 will use minikube and Kubernetes Version 1.23
* Debian 11, Ubuntu 20/22 and CentOS/RHEL 8/9 will use vanilla Kubernetes 1.26.5 (this requires us to use TCP/9443 for the collector port)
* This will expect the installer binary to be in /usr/bin/installer
* This will auto-generate a values.yaml that the installer will use

## Sysdig Backend Versions Tested

* 5.1.8-1

## Installation

1. `cp installer-5.1.8-1 /usr/bin/installer`
2. `./install.sh`
3. Enter in your Quay Pull Secret
4. Enter in your Sysdig License
5. Enter in DNS Name for the installation.
6. Wait patiently
7. Do a happy dance!
