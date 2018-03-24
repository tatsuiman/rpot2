#!/bin/bash
ES_HOST="localhost"
function print_usage() {
    echo "Usage: $0 [-l host]" 1>&2
    exit 1
}
while [ "$1" != "" ]; do
    case $1 in
        -l | -host )
            ES_HOST=$2
            if [ "$ES_HOST" = "" ]; then
                echo "Error: Missing Elasticsearch URL"
                print_usage
                exit 1
            fi
            ;;

        -h | -help )
            print_usage
            exit 0
            ;;

         *)
            echo "Error: Unknown option $2"
            print_usage
            exit 1
            ;;
    esac
    shift 2
done

sudo service suricata stop
sudo service logstash stop
sudo service kafka stop

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
curl -XPUT ${ES_HOST}:9200/bro-test
curl -XPUT ${ES_HOST}:9200/suricata-test
./restore-mapping.sh -i bro.json -l ${ES_HOST}
./restore-mapping.sh -i suricata.json -l ${ES_HOST}
