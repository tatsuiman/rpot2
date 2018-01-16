mkdir -p ${1}
curl "localhost:9200/.kibana/${1}/${2}" | jq '._source' > ${1}/${3}.json
