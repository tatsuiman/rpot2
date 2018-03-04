#!/bin/sh
./escls-run.sh "echo y | sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack"
./escls-run.sh "sudo /usr/share/kibana/bin/kibana-plugin install x-pack"
./escls-run.sh "echo 'xpack.security.enabled: false' | sudo tee -a /etc/elasticsearch/elasticsearch.yml"

