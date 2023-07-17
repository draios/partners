#!/usr/bin/env bash

set -euo pipefail

# globals
MINIMUM_CPUS=32
MINIMUM_MEMORY_KB=64000000
MINIMUM_DISK_IN_GB=200
ADDITIONAL_IMAGES=(
  "sysdig/falco-rules-installer:latest"
)

function logError() { echo "$@" 1>&2; }

#log to file and stdout
log_file="/var/log/sysdig-installer.log"
exec &>> >(tee -a "$log_file")

if [[ "$EUID" -ne 0 ]]; then
  logError "This script needs to be run as root"
  logError "Usage: sudo ./$0"
  exit 1
fi

MINIKUBE_VERSION=v1.29.0
MINIKUBE_KUBERNETES_VERSION=v1.23.0
KUBEADM_KUBERNETES_VERSION="1.26.5-00"
DOCKER_VERSION=18.06.3
USE_MINIKUBE="true"
ROOT_LOCAL_PATH="/usr/bin"
QUAYPULLSECRET="PLACEHOLDER"
LICENSE="PLACEHOLDER"
DNSNAME="PLACEHOLDER"
AIRGAP_BUILD="false"
AIRGAP_INSTALL="false"
RUN_INSTALLER="false"
DELETE_SYSDIG="false"
INSTALLER_BINARY="installer"

function writeValuesYaml() {
  cat << EOM > values.yaml
size: small
quaypullsecret: $QUAYPULLSECRET
apps: monitor secure
storageClassProvisioner: hostPath
namespace: sysdig
elasticsearch:
  jvmOptions: -Xmx4g -Xms4g
  hostPathNodes:
    - $(hostname)
hostPathCustomPaths:
  cassandra: /var/lib/cassandra
  elasticsearch: /var/lib/elasticsearch
  postgresql: /var/lib/postgresql/data/pgdata
sysdig:
  secure:
    falcoRulesUpdater:
      enabled: true
    rapidResponse:
      enabled: true
  postgresql:
    hostPathNodes:
      - $(hostname)
  cassandra:
    jvmOptions: -Xmx4g -Xms4g
    hostPathNodes:
      - $(hostname)
  api:
    jvmOptions: -Xmx4g -Xms4g
  collector:
    jvmOptions: -Xmx4g -Xms4g
  dnsName: $DNSNAME
  admin:
    username: pov@sysdig.com
  collectorPort: $(setCollectorPort)
  license: $LICENSE
  resources:
    api:
      limits:
        memory: 6Gi
      requests:
        memory: 4Gi
    apiNginx:
      requests:
        cpu: 50m
        memory: 100Mi
    apiEmailRenderer:
      requests:
        cpu: 50m
        memory: 100Mi
    cassandra:
      limits:
        memory: 8Gi
      requests:
        cpu: 500m
        memory: 8Gi
    collector:
      limits:
        memory: 6Gi
      requests:
        cpu: 500m
        memory: 4Gi
    elasticsearch:
      limits:
        memory: 8Gi
      requests:
        cpu: 500m
        memory: 8Gi
    worker:
      requests:
        cpu: 500m
        memory: 1Gi
    anchore-catalog:
      requests:
        cpu: 250m
        memory: 500Mi
    anchore-policy-engine:
      requests:
        cpu: 250m
        memory: 500Mi
    anchore-worker:
      requests:
        cpu: 250m
        memory: 500Mi
    scanning-api:
      requests:
        cpu: 250m
        memory: 500Mi
    scanningalertmgr:
      requests:
        cpu: 250m
        memory: 500Mi
    scanning-retention-mgr:
      requests:
        cpu: 250m
        memory: 500Mi
    secure-prometheus:
      requests:
        cpu: 250m
        memory: 500Mi
    netsec-api:
      requests:
        cpu: 250m
        memory: 500Mi
    netsec-ingest:
      requests:
        cpu: 250m
        memory: 500Mi
    policy-advisor:
      requests:
        cpu: 250m
        memory: 500Mi
    scanning-reporting-worker:
      requests:
        cpu: 250m
        memory: 500Mi
    alertManager:
      requests:
        cpu: 500m
    alertNotifier:
      limits:
        memory: 2Gi
      requests:
        cpu: 500m
    alerter:
      requests:
        cpu: 500m
#agent:
#  collectorPort: $(setCollectorPort)
#  namespace: sysdig-agent
#  resources:
#    requests:
#      cpu: 250m
#      memory: 500m
EOM
}

function checkCPU() {
  local -r cpus=$(grep -c processor /proc/cpuinfo)

  if [[ $cpus -lt $MINIMUM_CPUS ]]; then
    logError "The number of cpus '$cpus' is less than the required number of cpus: '$MINIMUM_CPUS'"
    exit 1
  fi

  echo "Enough cpu ✓"
}

function checkMemory() {
  local -r memory=$(grep MemTotal /proc/meminfo | awk '{print $2}')

  if [[ $memory -lt $MINIMUM_MEMORY_KB ]]; then
    logError "The amount of memory '$memory' is less than the required amount of memory in kilobytes '$MINIMUM_MEMORY_KB'"
    exit 1
  fi

  echo "Enough memory ✓"
}

function checkDisk() {
  local -r diskSizeHumanReadable=$(df -h /var | tail -n1 | awk '{print $2}')
  local -r diskSize=${diskSizeHumanReadable%G}
  echo "diskSize: $diskSize"
  diskSizeInt=$(echo $diskSize | cut -d "." -f 1 | cut -d "," -f 1)
  echo "diskSizeInt: $diskSizeInt"

  if [[ $diskSizeInt -lt $MINIMUM_DISK_IN_GB ]]; then
    logError "The volume that holds the var directory needs a minimum of '$MINIMUM_DISK_IN_GB' but currently has '$diskSize'"
    exit 1
  fi

  echo "Enough disk ✓"
}

function checkInstaller() {
  if ! hash installer > /dev/null 2>&1; then
    logError "sysdig installer is not installed on this host. Install the sysdig installer to ${ROOT_LOCAL_PATH}/${INSTALLER_BINARY} and retry."
    exit 1
  fi

  echo "Sysdig Installer installed ✓"
}

function preFlight() {
  echo "Running preFlight checks"
  checkCPU
  checkMemory
  checkDisk
  checkInstaller
}

function askQuestions() {
  if [[ "${AIRGAP_BUILD}" != "true" ]]; then
    read -rp $'Provide quay pull secret: \n' QUAYPULLSECRET
    printf "\n"
    read -rp $'Provide sysdig license: \n' LICENSE
    printf "\n"
    read -rp $'Provide domain name, this domain name should resolve to this node on port 443 and 6443: \n' DNSNAME
    printf "\n"
  else
    local -r quayPullSecret="${QUAYPULLSECRET}"
    if [[ "$quayPullSecret" == "PLACEHOLDER" ]]; then
      logError "-q|--quaypullsecret is needed for airgap build"
      exit 1
    fi
  fi
}

function setCollectorPort() {
  # if we use Minikube we will use the standard TCP/6443 for the collectorPort
  # when using kubeadm we have to use TCP/9443 as 6443 is used by the K8s API Server
  if [[ "USE_MINIKUBE" != "true" ]]; then
    echo "9443"
  else
    echo "6443"
  fi
}

function dockerLogin() {
  local -r quayPullSecret=$QUAYPULLSECRET
  if [[ "$quayPullSecret" != "PLACEHOLDER" ]]; then
    local -r auth=$(echo "$quayPullSecret" | base64 --decode | jq -r '.auths."quay.io".auth' | base64 --decode)
    local -r quay_username=${auth%:*}
    local -r quay_password=${auth#*:}
    docker login -u "$quay_username" -p "$quay_password" quay.io
  else
    logError "Please rerun the script and configure quay pull secret"
    exit 1
  fi
}

function installUbuntuDeps() {
  local -r version=$1
  apt-get remove -y docker docker-engine docker.io containerd runc > /dev/null 2>&1
  apt-get update -qq
  apt-get install -y apt-transport-https ca-certificates curl software-properties-common "linux-headers-$(uname -r)" conntrack jq vim snapd
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
  add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu  $(lsb_release -cs) stable"
  apt-get update -qq
  if [[ "${version}" =~ ^(bionic|xenial)$ ]]; then
    apt-get install -y --allow-unauthenticated docker-ce=${DOCKER_VERSION}~ce~3-0~ubuntu
  else
  USE_MINIKUBE="false"
  cat > /etc/modules-load.d/containerd.conf <<EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter
# Setup required sysctl params, these persist across reboots.
cat > /etc/sysctl.d/99-kubernetes-cri.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
  sysctl --system
  
  ### Install required packages
  apt install -y lvm2 curl jq conntrack
  
  ## Add docker repository as we need containerd.io
  #dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
  apt install -y containerd.io
  
  ## Configure containerd
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
  
  systemctl enable containerd
  systemctl restart containerd
  
  # setup crictl to use containerd socket
  cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 2
debug: false
pull-image-on-create: false
EOF

  curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add
  sudo apt-add-repository -y "deb http://apt.kubernetes.io/ kubernetes-xenial main"
  apt update -qq
  
  #Install Kubernetes (kubeadm, kubelet and kubectl) 
  apt-mark unhold kubeadm kubectl kubelet
  apt install -y kubeadm=${KUBEADM_KUBERNETES_VERSION} kubelet=${KUBEADM_KUBERNETES_VERSION} kubectl=${KUBEADM_KUBERNETES_VERSION} 
  apt-mark hold kubeadm kubectl kubelet
  
  #enable kubelet on boot
  systemctl enable kubelet
  
  K8S_VERSION=$(echo ${KUBEADM_KUBERNETES_VERSION} |cut -f1 -d-)
  kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version ${K8S_VERSION}
  
  mkdir -p $HOME/.kube 
  cp -i /etc/kubernetes/admin.conf $HOME/.kube/config  
  chown $(id -u):$(id -g) $HOME/.kube/config
  
  i=0
  fail=0
  while [ $i -lt 10 ]; do
    out=$(kubectl cluster-info 2>&1) || { fail=1; }
    if [ $fail -eq 0 ]; then
      # install calico 3.25.0
      kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/tigera-operator.yaml
      kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/custom-resources.yaml
      
      # untaint the control-plane node for single node  use
      kubectl taint nodes --all node-role.kubernetes.io/control-plane-
      kubectl taint nodes --all node-role.kubernetes.io/master-
      break
    else
      echo "Waiting for API Server"
      fail=1
      i=$((i+1))
    fi
    sleep 5
  done
  
  if [ $fail -eq 1 ]; then
    echo "Wasn't able to apply Calico or untaint nodes.  Please check containerd and kubelet for errors."
  fi
  fi
}

function installDebianDeps() {
  local -r version=$1
  apt-get remove -y docker docker-engine docker.io containerd runc > /dev/null 2>&1
  apt-get update -qq
  apt-get install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common "linux-headers-$(uname -r)" conntrack vim jq snapd
  curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
  add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
  apt-get update -qq
  if [[ "${version}" =~ ^(stretch|buster)$ ]]; then
  	apt-get install -y --allow-unauthenticated docker-ce=${DOCKER_VERSION}~ce~3-0~debian
  else
  USE_MINIKUBE="false"
  cat > /etc/modules-load.d/containerd.conf <<EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter
# Setup required sysctl params, these persist across reboots.
cat > /etc/sysctl.d/99-kubernetes-cri.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
  sysctl --system
  
  ### Install required packages
  apt install -y lvm2 curl jq conntrack
  
  ## Add docker repository as we need containerd.io
  #dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
  apt install -y containerd.io
  
  ## Configure containerd
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
  
  systemctl enable containerd
  systemctl restart containerd
  
  # setup crictl to use containerd socket
  cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 2
debug: false
pull-image-on-create: false
EOF

  curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add
  sudo apt-add-repository -y "deb http://apt.kubernetes.io/ kubernetes-xenial main"
  apt update -qq
  
  #Install Kubernetes (kubeadm, kubelet and kubectl) 
  apt-mark unhold kubeadm kubectl kubelet
  apt install -y kubeadm=${KUBEADM_KUBERNETES_VERSION} kubelet=${KUBEADM_KUBERNETES_VERSION} kubectl=${KUBEADM_KUBERNETES_VERSION} 
  apt-mark hold kubeadm kubectl kubelet
  
  #enable kubelet on boot
  systemctl enable kubelet
  
  K8S_VERSION=$(echo ${KUBEADM_KUBERNETES_VERSION} |cut -f1 -d-)
  kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version ${K8S_VERSION}
  
  mkdir -p $HOME/.kube 
  cp -i /etc/kubernetes/admin.conf $HOME/.kube/config  
  chown $(id -u):$(id -g) $HOME/.kube/config
  
  i=0
  fail=0
  while [ $i -lt 10 ]; do
    out=$(kubectl cluster-info 2>&1) || { fail=1; }
    if [ $fail -eq 0 ]; then
      # install calico 3.25.0
      kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/tigera-operator.yaml
      kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/custom-resources.yaml
      
      # untaint the control-plane node for single node  use
      kubectl taint nodes --all node-role.kubernetes.io/control-plane-
      kubectl taint nodes --all node-role.kubernetes.io/master-
      break
    else
      echo "Waiting for API Server"
      fail=1
      i=$((i+1))
    fi
    sleep 5
  done
  
  if [ $fail -eq 1 ]; then
    echo "Wasn't able to apply Calico or untaint nodes.  Please check containerd and kubelet for errors."
  fi
  fi
}

function installCentOSDeps() {
  local -r version=$1
  yum remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
  yum -y update
  yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
  if [[ $version == 8 ]]; then
    yum install -y yum-utils device-mapper-persistent-data lvm2 curl conntrack vim snapd
  else
    yum install -y yum-utils device-mapper-persistent-data lvm2 curl conntrack vim snapd
  fi
  # Copied from https://github.com/kubernetes/kops/blob/b92babeda277df27b05236d852b5c0dc0803ce5d/nodeup/pkg/model/docker.go#L758-L764
  yum install -y http://vault.centos.org/7.6.1810/extras/x86_64/Packages/container-selinux-2.68-1.el7.noarch.rpm
  yum install -y https://download.docker.com/linux/centos/7/x86_64/stable/Packages/docker-ce-18.06.3.ce-3.el7.x86_64.rpm
  yum install -y "kernel-devel-$(uname -r)"
}

function installRhelOSDeps() {
  local -r version=$1
  yum remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
  yum -y update
  yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
  yum install -y yum-utils device-mapper-persistent-data lvm2 curl conntrack vim snapd
  # Copied from https://github.com/kubernetes/kops/blob/b92babeda277df27b05236d852b5c0dc0803ce5d/nodeup/pkg/model/docker.go#L758-L764
  yum install -y http://vault.centos.org/7.6.1810/extras/x86_64/Packages/container-selinux-2.68-1.el7.noarch.rpm
  yum install -y https://download.docker.com/linux/centos/7/x86_64/stable/Packages/docker-ce-18.06.3.ce-3.el7.x86_64.rpm
  yum install -y "kernel-devel-$(uname -r)"
}

function installRhel8OSDeps() {
  local -r version=$1
  setenforce 0
  sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

  swapoff -a
  
  # turn off firewalld
  systemctl disable firewalld --now
  
  cat > /etc/modules-load.d/containerd.conf <<EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter
# Setup required sysctl params, these persist across reboots.
cat > /etc/sysctl.d/99-kubernetes-cri.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
  sysctl --system
  
  # run update on system
  dnf update -y
  
  ### Install required packages
  dnf install -y  yum-utils device-mapper-persistent-data lvm2 curl conntrack kernel-devel jq kernel-devel-$(uname -r) vim snapd
  
  ## Add docker repository as we need containerd.io
  dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
  dnf install -y containerd.io
  
  ## Configure containerd
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
  
  systemctl enable containerd
  systemctl restart containerd
  
  # setup crictl to use containerd socket
  cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 2
debug: false
pull-image-on-create: false
EOF
  
  cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
  
  #Install Kubernetes (kubeadm, kubelet and kubectl) 
  K8S_VERSION=$(echo ${KUBEADM_KUBERNETES_VERSION} | cut -f1 -d-)
  dnf install -y kubeadm-${K8S_VERSION} kubelet-${K8S_VERSION} kubectl-${K8S_VERSION} --disableexcludes=kubernetes
  
  #enable kubelet on boot
  systemctl enable kubelet
  
  kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version ${K8S_VERSION}
  
  mkdir -p $HOME/.kube 
  cp -i /etc/kubernetes/admin.conf $HOME/.kube/config  
  chown $(id -u):$(id -g) $HOME/.kube/config
  
  i=0
  fail=0
  while [ $i -lt 10 ]; do
    out=$(kubectl cluster-info 2>&1) || { fail=1; }
    if [ $fail -eq 0 ]; then
      # install calico 3.25.0
      kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/tigera-operator.yaml
      kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/custom-resources.yaml
      
      # untaint the control-plane node for single node  use
      kubectl taint nodes --all node-role.kubernetes.io/control-plane-
      kubectl taint nodes --all node-role.kubernetes.io/master-
      break
    else
      echo "Waiting for API Server"
      fail=1
      i=$((i+1))
    fi
    sleep 5
  done
  
  if [ $fail -eq 1 ]; then
    echo "Wasn't able to apply Calico or untaint nodes.  Please check containerd and kubelet for errors."
  fi
}

function disableFirewalld() {
  echo "Disabling firewald...."
  systemctl stop firewalld
  systemctl disable firewalld
}

function installMiniKube() {
  if [[ "${USE_MINIKUBE}" == "true" ]]; then
    curl -s -Lo minikube "https://storage.googleapis.com/minikube/releases/${MINIKUBE_VERSION}/minikube-linux-amd64"
    chmod +x minikube
    mv minikube "${ROOT_LOCAL_PATH}"
  fi
}

function installKubectl() {
  if [[ "${USE_MINIKUBE}" == "true" ]]; then
    curl -s -Lo kubectl "https://storage.googleapis.com/kubernetes-release/release/${MINIKUBE_KUBERNETES_VERSION}/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl "${ROOT_LOCAL_PATH}"
  fi
}

function installJq() {
  curl -o jq -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
  chmod +x jq
  mv jq "${ROOT_LOCAL_PATH}"
}

function installDeps() {
  set +e

  cat << EOF > /etc/sysctl.d/k8s.conf
  net.bridge.bridge-nf-call-ip6tables = 1
  net.bridge.bridge-nf-call-iptables = 1
  net.ipv4.ip_forward = 1
EOF
  modprobe br_netfilter
  swapoff -a
  systemctl mask '*.swap'
  sed -i.bak '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
  sysctl --system

  source /etc/os-release
  case $ID in
    ubuntu)
      if [[ ! $VERSION_CODENAME =~ ^(bionic|focal|jammy|xenial)$ ]]; then
        logError "ubuntu version: $VERSION_CODENAME is not supported"
        exit 1
      fi
      installUbuntuDeps $VERSION_CODENAME
      ;;
    debian)
      if [[ ! $VERSION_CODENAME =~ ^(stretch|buster|bullseye)$ ]]; then
        logError "debian version: $VERSION_CODENAME is not supported"
        exit 1
      fi
      installDebianDeps $VERSION_CODENAME
      ;;
    centos | amzn)
      if [[ $ID =~ ^(centos)$ ]] &&
        [[ ! "$VERSION_ID" =~ ^(7|8|9) ]]; then
        logError "$ID version: $VERSION_ID is not supported"
        exit 1
      fi
      if [[ "$VERSION_ID" =~ ^(7) ]]; then
      	disableFirewalld
        installCentOSDeps "$VERSION_ID"
      elif [[ "$VERSION_ID" =~ ^(8|9) ]]; then
        USE_MINIKUBE="false"
        disableFirewalld
        installRhel8OSDeps "$VERSION_ID"
      fi
      ;;
    rhel)
      if [[ $ID =~ ^(rhel)$ ]] &&
        [[ ! "$VERSION_ID" =~ ^(7|8|9) ]]; then
        echo "$ID version: $VERSION_ID is not supported"
        exit 1
      fi
      if [[ "$VERSION_ID" =~ ^(7) ]]; then
      	disableFirewalld
      	installRhelOSDeps "$VERSION_ID"
      elif [[ "$VERSION_ID" =~ ^(8|9) ]]; then
        USE_MINIKUBE="false"
        disableFirewalld
        installRhel8OSDeps "$VERSION_ID"
      fi
      
      ;;
    *)
      logError "unsupported platform $ID"
      exit 1
      ;;
  esac
  startDocker
  installJq
  installMiniKube
  installKubectl
  setSystemctlVmMaxMapCount
  writeEtcHosts

  set -e
}

function writeEtcHosts() {
  if ! grep -q "127.0.0.1 ${DNSNAME}" /etc/hosts; then
    #for sni agents to connect to collector via 127.0.0.1
    echo -e "\n#setting hostname for agents to connect" >> /etc/hosts
    echo -e "127.0.0.1 ${DNSNAME}" >> /etc/hosts
  fi
}

function setSystemctlVmMaxMapCount() {
    #set for running ElasticSearch as non-root
    VM_MAX_MAP_COUNT=${VM_MAX_MAP_COUNT:-262144}
    readonly VM_MAX_MAP_COUNT
    sysctl -w vm.max_map_count="${VM_MAX_MAP_COUNT}" | tee -a /etc/sysctl.conf
}

function startDocker() {
  if [[ "${USE_MINIKUBE}" == "true" ]]; then
    systemctl enable docker
    systemctl start docker
  fi
}

#There is a work around for a bug in minikube
function setDocker0Promisc() {
  if [[ "${USE_MINIKUBE}" == "true" ]]; then
    mkdir -p /usr/lib/systemd/system/
    cat << EOF > /usr/lib/systemd/system/docker0-promisc.service
[Unit]
Description=Setup promisc on docker0 interface
Wants=docker.service
After=docker.service
[Service]
Type=oneshot
ExecStart=/sbin/ip link set docker0 promisc on
RemainAfterExit=true
StandardOutput=journal
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable docker0-promisc
    systemctl start docker0-promisc
  fi
}

function startMinikube() {
  export MINIKUBE_HOME="/root"
  export KUBECONFIG="/root/.kube/config"
  minikube start --vm-driver=none --kubernetes-version=${MINIKUBE_KUBERNETES_VERSION}
  systemctl enable kubelet
  kubectl config use-context minikube
  minikube update-context
}

function fixIptables() {
  echo "Fixing iptables ..."
  ### Install iptables rules because minikube locks out external access
  iptables -I INPUT -t filter -p tcp --dport 443 -j ACCEPT
  iptables -I INPUT -t filter -p tcp --dport 6443 -j ACCEPT
  iptables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

function pullImagesSysdigImages() {
  #find images in resources
  mapfile -t non_job_images < <(jq -r '.spec.template.spec.containers[]? | .image' \
    /opt/sysdig-chart/resources/*/sysdig.json 2> /dev/null | sort -u | grep 'quay\|docker.io')
  mapfile -t job_images < <(jq -r '.spec.jobTemplate.spec.template.spec.containers[]? | .image' \
    /opt/sysdig-chart/resources/*/sysdig.json 2> /dev/null | sort -u | grep 'quay\|docker.io')
  mapfile -t init_container_images < <(jq -r '.spec.template.spec.initContainers[]? | .image' \
    /opt/sysdig-chart/resources/*/sysdig.json 2> /dev/null | sort -u | grep 'quay\|docker.io')
  #collected images  to images obj
  local -a images=("${non_job_images[@]}")
  images+=("${ADDITIONAL_IMAGES[@]}")
  images+=("${job_images[@]}")
  images+=("${init_container_images[@]}")
  #iterate and pull image if not present
  for image in "${images[@]}"; do
    if [[ -z $(docker images -q "$image") ]]; then
      logger info "Pulling $image"
      docker pull "$image" || true
    else
      echo "$image is present"
    fi
  done
  #clean up resources
  rm -rf /opt/sysdig-chart
}

function runInstaller() {
  if [[ "${AIRGAP_BUILD}" == "true" ]]; then
    dockerLogin
    pullImagesSysdigImages
  else
    writeValuesYaml
    ${INSTALLER_BINARY} deploy
  fi
}

function __main() {

  if [[ "${DELETE_SYSDIG}" == "true" ]]; then
    data_directories=$(kubectl get pv -o json | jq -r '.items[].spec.hostPath.path')
    kubectl delete ns sysdig || true
    kubectl delete ns agent || true
    kubectl delete pv --all || true
    for data_directory in ${data_directories}
    do
      echo "deleting ${data_directory}"
      rm -rf "${data_directory}"
    done
    exit 0
  fi

  if [[ "${RUN_INSTALLER}" == "true" ]]; then
    #single node installer just runs installer and returns early
    writeValuesYaml
    ${INSTALLER_BINARY} deploy
    exit 0
  fi
  preFlight
  askQuestions
  if [[ "${AIRGAP_INSTALL}" != "true" ]]; then
    installDeps
    setDocker0Promisc
  fi
  #minikube needs to run to set the correct context & ip during airgap run
  if [[ "${USE_MINIKUBE}" == "true" ]]; then
    startMinikube
  fi
  if [[ "${AIRGAP_INSTALL}" != "true" ]]; then
    fixIptables
  fi
  writeValuesYaml
}

while [[ $# -gt 0 ]]; do
  arguments="$1"

  case "${arguments}" in
    -a | --airgap-build)
      AIRGAP_BUILD="true"
      LICENSE="installer.airgap.license"
      DNSNAME="installer.airgap.dnsname"
      shift # past argument
      ;;
    -i | --airgap-install)
      AIRGAP_INSTALL="true"
      LICENSE="installer.airgap.license"
      DNSNAME="installer.airgap.dnsname"
      shift # past argument
      ;;
    -r | --run-installer)
      RUN_INSTALLER="true"
      shift # past value
      ;;
    -q | --quaypullsecret)
      QUAYPULLSECRET="$2"
      shift # past argument
      shift # past value
      ;;
    -d | --delete-sysdig)
      DELETE_SYSDIG="true"
      shift # past value
      ;;
    -h | --help)
      echo "Help..."
      echo "-a | --airgap-builder to specify airgap builder"
      echo "-i | --airgap-install to run as airgap install mode"
      echo "-r | --run-installer  to run the installer alone"
      echo "-q | --quaypullsecret followed by quaysecret to specify airgap builder"
      echo "-d | --delete-sysdig deletes sysdig namespace, persistent volumes and data from disk"
      shift # past argument
      exit 0
      ;;
    *) # unknown option
      shift # past argument
      logError "unknown arg $1"
      exit 1
      ;;
  esac
done

__main
