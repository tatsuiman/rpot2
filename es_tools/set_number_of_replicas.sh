curl -XPUT 'http://localhost:9200/bro-*/_settings' -d "
{
    \"index\" : {
        \"number_of_replicas\" : ${1}
    }
}"
