#!/bin/bash
elasticdump --input="http://localhost:9200/${1}*" --output=$ | gzip > ${1}.json.gz
# DELETE after
#curl -XDELETE "http://localhost:9200/${1}*"
