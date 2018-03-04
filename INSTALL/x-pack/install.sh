#!/bin/bash
# install x-pack
echo y | sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack
sudo /usr/share/kibana/bin/kibana-plugin install x-pack
echo 'xpack.security.enabled: false' | sudo tee -a /etc/elasticsearch/elasticsearch.yml
sudo service elasticsearch restart
sudo service kibana restart
