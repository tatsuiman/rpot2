#!/bin/bash
infile=${1}
index=$(basename -s .json.gz ${infile})
gzip -dc ${infile} | elasticdump --input=$ --output="http://localhost:9200/${index}"
