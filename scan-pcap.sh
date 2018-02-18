#!/bin/sh
cp ./config/${2}-hunter.bro ./config/output.bro
sed -i -e "s/sensor-001/${3}/g" ./config/output.bro
/usr/local/bro/bin/bro -r ${1} ./config/output.bro
sudo suricata -c /usr/local/etc/suricata/suricata.yaml -r $1
#cd ./hunting
#./run.sh
