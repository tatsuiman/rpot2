sudo cp -r area3d_vis network_vis /usr/share/kibana/plugins/
cd /usr/share/kibana/plugins/
cd ./area3d_vis
sudo /usr/share/kibana/node/bin/npm install
cd ..
cd ./network_vis
sudo /usr/share/kibana/node/bin/npm install
cd ../
