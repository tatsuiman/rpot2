#!/bin/bash
# Download and install sophos-av
sudo /opt/sophos-av/bin/savconfig set DisableFanotify true
sudo /opt/sophos-av/bin/savconfig set DisableFeedback true
sudo /opt/sophos-av/bin/savconfig add ExcludeFilePaths /tmp
sudo /opt/sophos-av/bin/savconfig add ExcludeFilePaths /opt/rpot/sample-pcap/
sudo /opt/sophos-av/bin/savconfig add ExcludeFilesystems nfs
sudo /opt/sophos-av/bin/savconfig add ExcludeFilesystems cifs
sudo /opt/sophos-av/bin/savconfig set ScanArchives enabled
sudo /opt/sophos-av/bin/savconfig set UploadSamples false
sudo /opt/sophos-av/bin/savconfig set SendThreatEmail disabled
sudo /opt/sophos-av/bin/savupdate
sudo /opt/sophos-av/bin/savdctl enable
sudo cp logstash-sophosav-es.conf /etc/logstash/conf.d/
