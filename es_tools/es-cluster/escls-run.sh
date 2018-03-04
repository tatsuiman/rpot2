#!/bin/bash
# ./escls-run.sh command
source config.sh
cmd=${1} 
for i in $(seq $node_num)
do
	for j in $(seq $shard_num)
	do
		lxc exec es-node${i}-shard${j} -- sh -c "$cmd"
	done
done
