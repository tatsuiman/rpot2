curl -XPUT 'http://localhost:9200/bro-*/_settings' -d "
{
    \"index\" : {
        \"refresh_interval\" : ${1}
    }
}"
