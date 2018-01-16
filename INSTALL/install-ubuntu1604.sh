#!/bin/bash
INSTALL_USER=$USER
is_failed() {
	if [ $? -ne 0 ]; then
		echo "The command was not successful.";
		exit 1
	fi;
}
# ask install x-pack
# You need register license (https://register.elastic.co/registration/)
INSTALL_XPACK='N'

# Java install
sudo apt -y update
sudo add-apt-repository ppa:webupd8team/java -y
sudo apt -y update
echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | sudo debconf-set-selections
echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 seen true" | sudo debconf-set-selections
sudo apt -y install oracle-java8-installer

# upgrade
sudo apt -y upgrade

sudo git clone http://github.com/tatsu-i/rpot  /opt/rpot
sudo chown ${INSTALL_USER}:${INSTALL_USER} -R /opt/rpot
cd /opt/rpot/INSTALL
sudo mkdir -p /opt/rpot/extract_files/
sudo chmod 777 /opt/rpot/extract_files/

# install bro
cd ./bro
tar zxpvf ./bro.tar.gz
sudo apt -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libgeoip-dev zookeeperd autoconf python-pip python3-pip jq curl wget
cd ./bro/
./configure
make -j 4
is_failed
sudo make install
sudo ln -s /usr/local/bro/bin/bro /usr/local/bin
cd ..

# bro service install
ETH=$(ifconfig -a | sed 's/[ \t].*//;/^$/d' |head -n 1)
sudo cp bro.service /lib/systemd/system/bro.service
sudo sed -i -e "s/__ETH__/${ETH}/g" /lib/systemd/system/bro.service 
sudo systemctl enable bro.service
cd ..

# install bro kafka plugin
cd kafka
tar zxpvf librdkafka.tar.gz
cd librdkafka-0.9.4
./configure --enable-sasl
make -j 4
is_failed
sudo make install
sudo ldconfig
cd ..
tar zxpvf metron-bro-plugin-kafka.tar.gz
cd metron-bro-plugin-kafka
./configure --bro-dist=../../bro/bro
make -j 4
is_failed
sudo make install
cd ..

# install kafka service
sudo mkdir -p /opt/kafka && sudo tar -xvf kafka_2.12-1.0.0.tgz -C /opt/kafka
sudo cp kafka.service /lib/systemd/system/kafka.service
cd ..

# install suricata
cd ./suricata/
./install.sh
cd ..

# install clamav
cd ./clamav-install
./install.sh
cd ..

# install suricata
cd ./suricata
./install.sh
cd ..

# install node elasticdump
sudo apt -y install nodejs npm
sudo npm cache clean
sudo npm install n -g
sudo n stable
sudo ln -sf /usr/local/bin/node /usr/bin/node
sudo apt-get purge -y nodejs npm
sudo npm install elasticdump -g

# install ELK
wget https://artifacts.elastic.co/downloads/kibana/kibana-5.5.2-amd64.deb
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.5.2.deb
wget https://artifacts.elastic.co/downloads/logstash/logstash-5.5.2.deb
sudo dpkg -i *.deb
sudo usermod -a -G adm logstash
sudo cp ./logstash/logstash-kafka-bro.conf /etc/logstash/conf.d
sudo cp ./logstash/logstash-suricata-es.conf /etc/logstash/conf.d
sudo cp ./logstash/logstash-clamav-es.conf /etc/logstash/conf.d/

# install logstash plugins
sudo /usr/share/logstash/bin/logstash-plugin install logstash-output-exec

# install kibana plugins
cd ./kibana-plugin
./install.sh
cd ..

# register and start service
sudo systemctl enable zookeeper
sudo systemctl start zookeeper
sudo systemctl enable kafka.service
sudo systemctl start kafka.service
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
sudo systemctl enable kibana.service
sudo systemctl start kibana.service
sudo systemctl enable logstash.service
sudo systemctl start logstash.service

# wait elasticsearch
while ! nc -z localhost 9200; do   
  sleep 0.1
done

# install x-pack
case $INSTALL_XPACK in
	Y)
		echo -n 'license json file path: '
		read $license_file
		echo y | sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack
		sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack
		echo 'xpack.security.enabled: false' | sudo tee -a /etc/elasticsearch/elasticsearch.yml
		curl -XPUT -u elastic:changeme 'http://localhost:9200/_xpack/license?acknowledge=true' -H "Content-Type: application/json" -d @${license_file}
		sudo service elasticsearch restart
		sudo service kibana restart
		;;
	*)
		echo -e "x-pack not installed."
		;;
esac

# init database
cd /opt/rpot
./init.sh
./update.sh

# install elastalert
cd /opt/rpot/INSTALL/elastalert
./install.sh
