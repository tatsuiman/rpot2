#!/bin/bash
source ./config.sh
function main() {
	trap catch ERR
	for i in $(seq $node_num)
	do
		for j in $(seq $shard_num)
		do
			lxc launch ubuntu:16.04 es-node${i}-shard${j}
		done
	done
	sleep 10
	uhosts=$(echo -n 'discovery.zen.ping.unicast.hosts:  ["';for i in $(seq $node_num); do for j in $(seq $shard_num); do lxc list es-node${i}-shard${j} -c 4|awk '!/IPV4/{if ( $2 != "" ) print $2 }'; done; done |tr "\n" ","|sed -e 's/,/","/g' |sed -e 's/,"$/]/g')

	if [ ! -e elasticsearch-6.2.2.deb ]; then
		wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.2.2.deb -O elasticsearch-6.2.2.deb
	fi
	for i in $(seq $node_num)
	do
		for j in $(seq $shard_num)
		do
			lxc file push elasticsearch-6.2.2.deb es-node${i}-shard${j}/root/
			lxc exec es-node${i}-shard${j} -- sh -c "add-apt-repository ppa:webupd8team/java -y && apt-get update"
			lxc exec es-node${i}-shard${j} -- sh -c "echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 select true' | debconf-set-selections"
			lxc exec es-node${i}-shard${j} -- sh -c "echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 seen true' | debconf-set-selections"
			lxc exec es-node${i}-shard${j} -- sh -c "apt -y install oracle-java8-installer"
			lxc exec es-node${i}-shard${j} -- sh -c "dpkg -i elasticsearch-6.2.2.deb"
			lxc exec es-node${i}-shard${j} -- sh -c "echo 'cluster.name: rpot-cls' |tee -a /etc/elasticsearch/elasticsearch.yml"
			lxc exec es-node${i}-shard${j} -- sh -c "echo node.name: node-${i} |tee -a /etc/elasticsearch/elasticsearch.yml"
			lxc exec es-node${i}-shard${j} -- sh -c "echo 'network.host: 0.0.0.0' |tee -a /etc/elasticsearch/elasticsearch.yml"
			lxc exec es-node${i}-shard${j} -- sh -c "echo '$uhosts'|tee -a /etc/elasticsearch/elasticsearch.yml"
			lxc exec es-node${i}-shard${j} -- sh -c "echo discovery.zen.minimum_master_nodes: $master_node_num |tee -a /etc/elasticsearch/elasticsearch.yml"
			lxc exec es-node${i}-shard${j} -- sh -c "echo 'network.publish_host: _eth0:ipv4_' |tee -a /etc/elasticsearch/elasticsearch.yml"
			lxc exec es-node${i}-shard${j} -- systemctl enable elasticsearch.service
		done
	done
	for i in $(seq $node_num)
	do
		for j in $(seq $shard_num)
		do
			lxc exec es-node${i}-shard${j} -- systemctl start elasticsearch.service
		done
	done
	return 0
}
 
function catch() {
	for i in $(seq $node_num)
	do
		for j in $(seq $shard_num)
		do
			lxc delete -f es-node${i}-shard${j}
		done
	done
}
function finally() {
	echo "Finish"
}
 
# Entry Point
set -eu
trap finally EXIT
main
