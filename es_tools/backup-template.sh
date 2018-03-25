#!/bin/bash
INDEX="bro"
ES_HOST="localhost"
function print_usage() {
    echo "Usage: $0 [-l host] [-i infile]" 1>&2
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

curl -s -XGET "http://${ES_HOST}:9200/_template/${INDEX}_index" | jq ".${INDEX}_index" |jq . > template_${INDEX}.json
