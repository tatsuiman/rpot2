#!/bin/bash
INDEX="bro"
ES_HOST="localhost"
function print_usage() {
    echo "Usage: $0 [-l host] [-i index]" 1>&2
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

        -i | -index )
            INDEX=$2
            if [ "$INDEX" = "" ]; then
                echo "Error: Missing index pattern"
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
elasticdump --input="http://${ES_HOST}:9200/${INDEX}*" --output=$ | gzip > ${INDEX}.json.gz

# DELETE after
#curl -XDELETE "http://localhost:9200/${1}*"
