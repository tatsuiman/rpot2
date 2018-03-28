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
mkdir -p /etc/logstash/conf.d/translate/
mkdir -p feed/private
cd ./feed
rm -rf ./maltrail
git clone https://github.com/stamparm/maltrail
rm /tmp/maltrail*.csv
for i in $(ls ./maltrail/trails/static/malware/*.txt)
do
	python ../bin/parse.py $i /tmp/maltrail
done

rm -rf ./blocklist-ipsets
git clone https://github.com/firehol/blocklist-ipsets
cd ./blocklist-ipsets
git checkout master
cd ..
rm /tmp/blocklist-ipsets*.csv
for i in $(ls ./blocklist-ipsets/*.ipset)
do
	python ../bin/parse.py $i /tmp/blocklist-ipsets
done

#rm -rf virusshare_hash
#git clone https://github.com/super-a1ice/virusshare_hash
#rm /tmp/virusshare_hash*.csv
#rm virusshare_hash/VirusShare_000*.md5
#rm virusshare_hash/VirusShare_001*.md5
#for i in $(ls ./virusshare_hash/*.md5)
#do
#	python ../bin/parse.py $i /tmp/virusshare_hash
#done
#sudo mv /tmp/virusshare_hash*.csv /etc/logstash/conf.d/translate/

wget http://www.rpot.net/shodan.txt -O shodan.txt
wget http://www.rpot.net/rapid7.txt -O rapid7.txt
python ../bin/parse.py shodan.txt /tmp/whitelist
python ../bin/parse.py rapid7.txt /tmp/whitelist
sudo mv /tmp/blocklist-ipsets-*.csv /tmp/maltrail*.csv /tmp/whitelist*.csv /etc/logstash/conf.d/translate/
wget http://www.rpot.net/alexa-top-1m.csv -O alexa-top-1m.csv
wget http://www.rpot.net/cisco-umbrella-top-1m.csv -O cisco-umbrella-top-1m.csv
sudo mv alexa-top-1m.csv cisco-umbrella-top-1m.csv /etc/logstash/conf.d/translate/

# update intel script
sudo oinkmaster -C /etc/oinkmaster.conf -o /usr/local/etc/suricata/rules/
