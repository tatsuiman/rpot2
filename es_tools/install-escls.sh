#!/bin/bash
sudo apt-get update
sudo apt-get install -y lxc2
lxc init
sudo systemctl stop lxd-bridge
sudo systemctl --system daemon-reload
sudo su -c 'cat <<EOF > /etc/default/lxd-bridge
USE_LXD_BRIDGE="true"
LXD_BRIDGE="lxdbr0"
UPDATE_PROFILE="true"
LXD_CONFILE=""
LXD_DOMAIN="lxd"
LXD_IPV4_ADDR="10.202.80.1"
LXD_IPV4_NETMASK="255.255.255.0"
LXD_IPV4_NETWORK="10.202.80.1/24"
LXD_IPV4_DHCP_RANGE="10.202.80.2,10.202.80.254"
LXD_IPV4_DHCP_MAX="252"
LXD_IPV4_NAT="true"
LXD_IPV6_ADDR=""
LXD_IPV6_MASK=""
LXD_IPV6_NETWORK=""
LXD_IPV6_NAT="false"
LXD_IPV6_PROXY="false"
EOF
'
sudo systemctl enable lxd-bridge
sudo systemctl start lxd-bridge
echo vm.max_map_count=262144 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo lxd init
sudo usermod -aG lxd $USER
sudo -u $USER ./create-escls.sh
