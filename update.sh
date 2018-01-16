#!/bin/bash

# update geoip
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
gzip -d GeoLiteCity.dat.gz
gzip -d GeoIPASNum.dat.gz
gzip -d GeoLiteCityv6.dat.gz
gzip -d GeoIP.dat.gz 
sudo mv GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat
sudo mv GeoIPASNum.dat /usr/share/GeoIP/GeoIPASNum.dat
sudo mv GeoLiteCityv6.dat /usr/share/GeoIP/GeoIPCityv6.dat
sudo mv GeoIP.dat /usr/share/GeoIP/GeoIP.dat

# update geoip for logstash
sudo mkdir -p /etc/logstash/geoipdbs/
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz
gunzip GeoLite2-Country.mmdb.gz
gunzip GeoLite2-City.mmdb.gz
tar zxpvf GeoLite2-ASN.tar.gz --strip-components=1 --wildcards '*.mmdb'
rm GeoLite2-ASN.tar.gz
sudo mv ./GeoLite2-City.mmdb /etc/logstash/geoipdbs/
sudo mv ./GeoLite2-Country.mmdb /etc/logstash/geoipdbs/
sudo mv ./GeoLite2-ASN.mmdb /etc/logstash/geoipdbs

# update feed
mkdir -p feed/private
cd ./feed
rm -rf ./maltrail
git clone https://github.com/stamparm/maltrail
for i in $(ls ./maltrail/trails/static/malware/*.txt)
do
	python ../bin/parse.py $i
done

rm -rf ./blocklist-ipsets
git clone https://github.com/firehol/blocklist-ipsets
cd ./blocklist-ipsets
git checkout master
cd ..
for i in $(ls ./blocklist-ipsets/*.ipset)
do
	python ../bin/parse.py $i
done

cd ..

# update hunting keyword list
#rm -rf virusshare_hash
#git clone https://github.com/super-a1ice/virusshare_hash
#cd ..

# update intel script
python bin/intel.py 'feed/maltrail/trails/static/malware/*.txt,feed/blocklist-ipsets/*.ipset,feed/private/*.intel' > config/intel-config.bro
sudo oinkmaster -C /etc/oinkmaster.conf -o /usr/local/etc/suricata/rules/

