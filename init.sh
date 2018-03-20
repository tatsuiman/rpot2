sudo service suricata stop
sudo service logstash stop
sudo service kafka stop
ES_HOST="localhost"

rm -rf extract_files/*
touch ./extract_files/empty

cd /opt/rpot/dashboards
/opt/kafka/kafka_2.12-1.0.0/bin/kafka-topics.sh --delete --zookeeper localhost:2181 --topic bro-raw
/opt/kafka/kafka_2.12-1.0.0/bin/kafka-topics.sh --delete --zookeeper localhost:2181 --topic bro-clean
curl -XDELETE "${ES_HOST}:9200/bro-*"
curl -XDELETE "${ES_HOST}:9200/suricata-*"
./load.sh
sudo rm /usr/local/var/log/suricata/eve.json
sudo service suricata start
sudo service logstash start
sudo service kafka start

cd /opt/rpot/es_tools
./restore-mapping.sh -i mapping_bro.json -l ${ES_HOST}
./restore-mapping.sh -i mapping_suricata.json -l ${ES_HOST}
