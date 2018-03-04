#!/bin/bash
# ./escls-ctl.sh start or stop or restart or status
source config.sh
op=${1} 
for i in $(seq $node_num)
do
	for j in $(seq $shard_num)
	do
		lxc exec es-node${i}-shard${j} -- sh -c "systemctl $op --no-pager elasticsearch"
	done
done
