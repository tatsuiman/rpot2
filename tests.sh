#!/bin/sh
for pf in $(find /opt/rpot/INSTALL/bro/bro/testing/btest/Traces -name "*.pcap")
do
	pcap_name=$(basename ${pf})
	echo "scan pcap ${pf}"
	cp ./config/quick-hunter.bro ./config/output.bro
	sed -i -e "s/sensor-001/${pcap_name}/g" ./config/output.bro
	/usr/local/bro/bin/bro -r ${pf} ./config/output.bro
done
