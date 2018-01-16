gzip -dc backup_bro.json.gz |elasticdump --input=$ --output='http://localhost:9200/bro-restore'  
gzip -dc backup_clamd.json.gz |elasticdump --input=$ --output='http://localhost:9200/clamd-restore'  
gzip -dc backup_suricata.json.gz |elasticdump --input=$ --output='http://localhost:9200/suricata-restore'  
