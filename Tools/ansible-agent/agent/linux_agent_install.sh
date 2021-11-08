#!/bin/bash
#
# Installer for Sysdig Agent
# www.draios.com
#
# (c) 2013-2015 Sysdig Inc.
#

set -e

function install_rpm {
	if ! hash curl > /dev/null 2>&1; then
		echo "* Installing curl"
		yum -q -y install curl
	fi

	if ! yum -q list dkms > /dev/null 2>&1; then
		echo "* Installing EPEL repository (for DKMS)"
		if [ $VERSION -eq 8 ]; then
			rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
		elif [ $VERSION -eq 7 ]; then
			rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
		else
			rpm --quiet -i https://archives.fedoraproject.org/pub/archive/epel/6/i386/epel-release-6-8.noarch.rpm
		fi
	fi

	echo "* Installing Sysdig public key"
	rpm --quiet --import https://download.sysdig.com/DRAIOS-GPG-KEY.public
	echo "* Installing Sysdig repository"
	curl -s -o /etc/yum.repos.d/draios.repo https://download.sysdig.com/stable/rpm/draios.repo
	echo "* Installing kernel headers"
	KERNEL_VERSION=$(uname -r)
	if [[ $KERNEL_VERSION == *PAE* ]]; then
		yum -q -y install kernel-PAE-devel-${KERNEL_VERSION%.PAE} || kernel_warning
	elif [[ $KERNEL_VERSION == *stab* ]]; then
		# It's OpenVZ kernel and we should install another package
		yum -q -y install vzkernel-devel-$KERNEL_VERSION || kernel_warning
	elif [[ $KERNEL_VERSION == *uek* ]]; then
		yum -q -y install kernel-uek-devel-$KERNEL_VERSION || kernel_warning
	else
		yum -q -y install kernel-devel-$KERNEL_VERSION || kernel_warning
	fi
	echo "* Installing Sysdig Agent"
	yum -q -y install draios-agent
}

function install_deb {
	export DEBIAN_FRONTEND=noninteractive

	if ! hash curl > /dev/null 2>&1; then
		echo "* Installing curl"
		apt-get -qq -y install curl < /dev/null
	fi

	echo "* Installing Sysdig public key"
	curl -s https://download.sysdig.com/DRAIOS-GPG-KEY.public | apt-key add -
	echo "* Installing Sysdig repository"
	curl -s -o /etc/apt/sources.list.d/draios.list https://download.sysdig.com/stable/deb/draios.list
	apt-get -qq update < /dev/null
	echo "* Installing kernel headers"
	apt-get -qq -y install linux-headers-$(uname -r) < /dev/null || kernel_warning
	echo "* Installing Sysdig Agent"
	apt-get -qq -y install draios-agent < /dev/null
}

function unsupported {
	echo "Unsupported operating system. Please consider contacting support@sysdigcloud.com or trying the manual installation."
	exit 1	
}

function kernel_warning {
	echo "Unable to find kernel development files for the current kernel version" $(uname -r)
	echo "This usually means that your system is not up-to-date or you installed a custom kernel version."
	echo "The installation will continue but you'll need to install these yourself in order to use the agent."
	echo "Contact support@sysdigcloud.com if you need further assistance."
}

function help {
	echo "Usage: $(basename ${0}) -a | --access_key <value> [-t | --tags <value>] [-c | --collector <value>] \ "
        echo "                [-cp | --collector_port <value>] [-s | --secure <value>] [-cc | --check_certificate] \ "
        echo "                [-ac | --additional_conf <value>] [-h | --help]"
	echo "  access_key: Secret access key, as shown in Sysdig Monitor"
	echo "  tags: List of tags for this host."
	echo "        The syntax can be a comma-separated list of"
	echo "        TAG_NAME:TAG_VALUE or a single TAG_VALUE (in which case the tag"
	echo "        name \"Tag\" is implicitly assumed)."
	echo "        For example, \"role:webserver,location:europe\", \"role:webserver\""
	echo "        and \"webserver\" are all valid alternatives."
	echo "  collector: collector IP for Sysdig Monitor on-premises installation"
	echo "  collector_port: collector port [default 6443]"
	echo "  secure: use a secure SSL/TLS connection to send metrics to the collector"
	echo "          accepted values: true or false [default true]"
	echo "  check_certificate: disable strong SSL certificate check for Sysdig Monitor on-premises installation"
	echo "          accepted values: true or false [default true]"
	echo "  additional_conf: If provided, will be appended to agent configuration file"
	echo "  help: print this usage and exit"
	echo
	exit 1
}

function is_valid_value {
	if [[ ${1} == -* ]] || [[ ${1} == --* ]] || [[ -z ${1} ]]; then
		return 1
	else
		return 0
	fi
}

#main
BACKWARD=false 

if [[ ${#} -eq 0 ]]; then
	echo "ERROR: sysdig-cloud access_key is mandatory, use -h | --help for $(basename ${0}) Usage"
	exit 1
fi

#backward for old agent options
if [[ ${#} -le 2 ]]; then
	if is_valid_value "${1}"; then
		if [[ ${1} =~ [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} ]]; then
			ACCESS_KEY="${1}"
			BACKWARD=true
		fi
	fi
	if is_valid_value "${2}"; then
		if [[ ! ${2} =~ [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} ]]; then
			TAGS="${2}"
		fi
	fi
fi

if [[ ${BACKWARD} != true ]]; then
	while [[ ${#} > 0 ]]
	do
	key="${1}"

	case ${key} in
		-a|--access_key)
			if is_valid_value "${2}"; then
				ACCESS_KEY="${2}"
			else
				echo "ERROR: no value provided for access_key option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-t|--tags)
			if is_valid_value "${2}"; then
				TAGS="${2}"
			else
				echo "ERROR: no value provided for tags option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-c|--collector)
			if is_valid_value "${2}"; then
				COLLECTOR="${2}"
			else
				echo "ERROR: no value provided for collector endpoint option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-cp|--collector_port)
			if is_valid_value "${2}"; then
				COLLECTOR_PORT="${2}"
			else
				echo "ERROR: no value provided for collector port option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-s|--secure)
			if is_valid_value "${2}"; then
				SECURE="${2}"
			else
				echo "ERROR: no value provided for connection security option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-cc|--check_certificate)
			if is_valid_value "${2}"; then
				CHECK_CERT="${2}"
			else
				echo "ERROR: no value provided for SSL check certificate option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-ac|--additional_conf)
			if is_valid_value "${2}"; then
				ADDITIONAL_CONF="${2}"
			else
				echo "ERROR: no value provided for additional conf option, use -h | --help for $(basename ${0}) Usage"
				exit 1
			fi
			shift
			;;
		-h|--help)
			help
			exit 1
			;;
		*)
			echo "ERROR: Invalid option: ${1}, use -h | --help for $(basename ${0}) Usage"
			exit 1
			;;
	esac
	shift
	done
fi

if [ $(id -u) != 0 ]; then
	echo "Installer must be run as root (or with sudo)."
	exit 1
fi

echo "* Detecting operating system"

ARCH=$(uname -m)
if [[ ! $ARCH = *86 ]] && [ ! $ARCH = "x86_64" ] && [ ! $ARCH = "s390x" ]; then
	unsupported
fi

if [ $ARCH = "s390x" ]; then
	echo "------------"
	echo "WARNING: A Docker container is the only officially supported platform on s390x"
	echo "------------"
fi

if [ -f /etc/debian_version ]; then
	if [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		DISTRO=$DISTRIB_ID
		VERSION=${DISTRIB_RELEASE%%.*}
	else
		DISTRO="Debian"
		VERSION=$(cat /etc/debian_version | cut -d'.' -f1)
	fi

	case "$DISTRO" in

		"Ubuntu")
			if [ $VERSION -ge 10 ]; then
				install_deb
			else
				unsupported
			fi
			;;

		"LinuxMint")
			if [ $VERSION -ge 9 ]; then
				install_deb
			else
				unsupported
			fi
			;;

		"Debian")
			if [ $VERSION -ge 6 ]; then
				install_deb
			elif [[ $VERSION == *sid* ]]; then
				install_deb
			else
				unsupported
			fi
			;;

		*)
			unsupported
			;;

	esac

elif [ -f /etc/system-release-cpe ]; then
	DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f3)

	# New Amazon Linux 2 distro
	if [[ -f /etc/image-id ]]; then
		AMZ_AMI_VERSION=$(cat /etc/image-id | grep 'image_name' | cut -d"=" -f2 | tr -d "\"")
	fi

	if [[ "${DISTRO}" == "o" ]] && [[ ${AMZ_AMI_VERSION} = *"amzn2"* ]]; then
		DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f4)
	fi

	VERSION=$(cat /etc/system-release-cpe | cut -d':' -f5 | cut -d'.' -f1 | sed 's/[^0-9]*//g')

	case "$DISTRO" in

		"oracle" | "centos" | "redhat")
			if [ $VERSION -ge 6 ]; then
				install_rpm
			else
				unsupported
			fi
			;;

		"amazon")
			install_rpm
			;;

		"fedoraproject")
			if [ $VERSION -ge 13 ]; then
				install_rpm
			else
				unsupported
			fi
			;;

		*)
			unsupported
			;;

	esac

else
	unsupported
fi

echo "* Setting access key"

CONFIG_FILE=/opt/draios/etc/dragent.yaml

if ! grep ^customerid $CONFIG_FILE > /dev/null 2>&1; then
	echo "customerid: $ACCESS_KEY" >> $CONFIG_FILE
else
	sed -i "s/^customerid.*/customerid: $ACCESS_KEY/g" $CONFIG_FILE
fi

if [ ! -z "$TAGS" ]; then
	echo "* Setting tags"

	if ! grep ^tags $CONFIG_FILE > /dev/null 2>&1; then
		echo "tags: $TAGS" >> $CONFIG_FILE
	else
		sed -i "s/^tags.*/tags: $TAGS/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$COLLECTOR" ]; then
	echo "* Setting collector endpoint"

	if ! grep ^collector: $CONFIG_FILE > /dev/null 2>&1; then
		echo "collector: $COLLECTOR" >> $CONFIG_FILE
	else
		sed -i "s/^collector:.*/collector: $COLLECTOR/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$COLLECTOR_PORT" ]; then
	echo "* Setting collector port"

	if ! grep ^collector_port $CONFIG_FILE > /dev/null 2>&1; then
		echo "collector_port: $COLLECTOR_PORT" >> $CONFIG_FILE
	else
		sed -i "s/^collector_port.*/collector_port: $COLLECTOR_PORT/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$SECURE" ]; then
	echo "* Setting connection security"

	if ! grep ^ssl: $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl: $SECURE" >> $CONFIG_FILE
	else
		sed -i "s/^ssl:.*/ssl: $SECURE/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$CHECK_CERT" ]; then
	echo "* Setting SSL certificate check level"

	if ! grep ^ssl_verify_certificate $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl_verify_certificate: $CHECK_CERT" >> $CONFIG_FILE
	else
		sed -i "s/^ssl_verify_certificate.*/ssl_verify_certificate: $CHECK_CERT/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$ADDITIONAL_CONF" ]; then
	echo "* Adding additional configuration to dragent.yaml"

	echo -e "$ADDITIONAL_CONF" >> $CONFIG_FILE
fi

service dragent restart
