sudo service suricata stop
sudo service logstash stop
sudo service kafka stop

rm -rf extract_files/*
touch ./extract_files/empty
cd dashboards
/opt/kafka/kafka_2.12-1.0.0/bin/kafka-topics.sh --delete --zookeeper localhost:2181 --topic bro-raw
/opt/kafka/kafka_2.12-1.0.0/bin/kafka-topics.sh --delete --zookeeper localhost:2181 --topic bro-clean
curl -XDELETE "localhost:9200/bro-*"
curl -XDELETE 'localhost:9200/suricata-*'
curl -XPUT 'http://localhost:9200/_template/bro_index' -d @mapping.json
./load.sh
sudo rm /usr/local/var/log/suricata/eve.json
sudo service suricata start
sudo service logstash start
sudo service kafka start
curl 'localhost:9200/_cat/indices?v'
