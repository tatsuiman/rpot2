#!/bin/sh
sudo apt -y install libssl-dev
sudo rm -rf ./clamav-0.99.3-beta1
tar zxpvf ./clamav-0.99.3-beta1.tar.gz
cd ./clamav-0.99.3-beta1
./configure
make -j 4
sudo make install
cd ..

sudo mkdir -p /usr/local/share/clamav

sudo cp clamd.service /lib/systemd/system/clamd.service
sudo cp clamd.conf /usr/local/etc/clamd.conf
sudo cp clamav-update /usr/local/bin/
sudo cp clamd-response /usr/local/bin/clamd-response

sudo cp ./rules/*.yar /usr/local/share/clamav/ 

sudo mkdir /var/log/clamav
sudo chown -R root:adm /var/log/clamav
sudo chmod 2755 /var/log/clamav

sudo ldconfig
sudo systemctl enable clamd
sudo systemctl start clamd

