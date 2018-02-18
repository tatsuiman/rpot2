## Real-time Packet Observation Tool (RPOT)


This build was created and tested using Ubuntu 16.04.


### architecture
![architecture](https://github.com/tatsu-i/rpot/raw/master/screenshot/architecture.png "architecture")


### Protocol coverage

| Protocol | Decode Payload |  ElasticSearch Output | Kibana Visualization |
| :--- | :---: | :---: | :---:|
| ARP  | ○ | × | × | 
| AYIYA  | ○ | × | × | 
| BackDoor |○ | × | × | 
| BitTorrent |○ | × | × | 
| DCE RPC  | ○ | ○ | × | 
| DHCP  | ○ | ○ | ○ | 
| DNP3  | ○ | ○ | × | 
| DNS  | ○ | ○ | ○ | 
| File  | ○ | ○ | ○ | 
| [Finger](https://en.wikipedia.org/wiki/Finger_protocol)  | ○ | × | × | 
| FTP  | ○ | ○ | × | 
| [Gnutella](http://en.wikipedia.org/wiki/Gnutella) | ○ | × | × | 
| GSSAPI | ○ | × | × | 
| GTPv1 | ○ | × | × | 
| HTTP | ○ | ○ | ○ | 
| ICMP | ○ | ○ | ○ | 
| [Ident](http://en.wikipedia.org/wiki/ident_protocol) | ○ | × | × | 
| IMAP | ○ | × | × | 
| IRC | ○ | ○ | ○ | 
| kerberos | ○ | ○ | × | 
| [Login](https://tools.ietf.org/html/rfc1258.html) | ○ | × | × | 
| [MIME](http://en.wikipedia.org/wiki/MIME) | ○ | × | × | 
| [Modbus](https://en.wikipedia.org/wiki/Modbus) | ○ | ○ | × | 
| MySQL | ○ | ○ | × | 
| NCP | ○ | × | × | 
| NetBios | ○ | ○ | ○ | 
| NTLM | ○ | ○ | ○ | 
| NTP | ○ | × | × | 
| OpenFlow | ○ | ○ | ○ | 
| POP3 | ○ | × | × | 
| RADIUS | ○ | ○ | × | 
| RDP | ○ | ○ | × | 
| RFB | ○ | ○ | × | 
| RPC | ○ | × | × | 
| SIP | ○ | ○ | × | 
| SMB | ○ | ○ | ○ | 
| SMTP | ○ | ○ | ○ | 
| SNMP | ○ | ○ | ○ | 
| SOCKS | ○ | ○ | × | 
| SSH | ○ | ○ | ○ | 
| SSL | ○ | ○ | ○ | 
| Syslog | ○ | ○ | × | 
| TCP | ○ | ○ | ○ | 
| [Teredo](https://tools.ietf.org/html/rfc4380.html) | ○ | ○ | × | 
| UDP | ○ | ○ | ○ | 
| XMPP | ○ | × | × | 
| ZIP | ○ | × | × | 

## Startup
```
$ wget https://raw.githubusercontent.com/tatsu-i/rpot/master/INSTALL/install-ubuntu1604.sh 
$ bash ./install-ubuntu1604.sh
```

## Usage
```
$ cd /opt/rpot
$ ./scan-pcap.sh [pcap file path] [intel|standard|quick] [scan name]
```

### Quick scan
```
$ cd /opt/rpot
$ ./update.sh
$ git clone https://github.com/tatsu-i/malware-traffic-analysis.net
$ ./scan-pcap.sh malware-traffic-analysis.net/2017-10-19-Necurs-Botnet-malspam-pushing-Locky.pcap quick test-quickscan
```

### Intelligence scan
```
$ cd /opt/rpot
$ ./update.sh
$ git clone https://github.com/tatsu-i/malware-traffic-analysis.net
$ ./scan-pcap.sh malware-traffic-analysis.net/2017-10-19-Necurs-Botnet-malspam-pushing-Locky.pcap intel test-intelscan
```

### Threat hunting
```
$ cd /opt/rpot
$ git clone https://github.com/tatsu-i/virusshare_hash
$ python ./bin/keyword-hunter.py virusshare_hash/*.md5 /tmp/hunting.log malware
```

### Update Geoip and Intelligence
```
$ cd /opt/rpot
$ ./update.sh
```

### Update hunting rule
```
$ cd /usr/local/share/clamav/
$ sudo vim sample.yar
rule Sample_Rule {
        strings:
            $string1 = "Test"

        condition:
            $string1
}
```

### FAME integration

See how to build FAME [FAME’s Documentation](https://fame.readthedocs.io/en/latest/).
and change logstash config
```
$ cd /opt/rpot/INSTALL
$ vim logstash-clamav-es.conf # modify API_KEY and Hostname
$ sudo cp logstash-clamav-es.conf /etc/logstash/conf.d/
$ sudo service logstash restart
```

### Visualization

Access Kibana url (``http://localhost:5601``)
Click [Dashboard] -> [Open] -> [MAIN]

![screenshot0](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot0.png "overview")
![screenshot1](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot1.png "HTTP")
![screenshot2](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot2.png "Intelligence")
![screenshot3](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot3.png "Connection")
![screenshot5](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot5.png "Files")
![screenshot6](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot6.png "Suricata")
![screenshot7](https://github.com/tatsu-i/rpot/raw/master/screenshot/screenshot7.png "SSL")
