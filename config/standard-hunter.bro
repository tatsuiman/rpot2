module SENSOR;
export {
  const sensor_id = "sensor-001" &redef;
}
# Load file extraction
#@load frameworks/files/detect-MHR
#@load ./frameworks/files/extraction
@load frameworks/files/extract-all-files
redef FileExtract::prefix = "/opt/rpot/extract_files/";
redef FileExtract::default_limit = 1048576000;
@load frameworks/files/hash-all-files

# Kafka config
@load ./scripts/plugins/kafka

# Add sensor and log meta information to each log
@load ./scripts/frameworks/logging/extension

# ignore checksum
redef ignore_checksums = T;

# protocol settings
@load base/frameworks/openflow
@load base/protocols/dhcp
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/krb
@load base/protocols/modbus
@load base/protocols/mysql
@load base/protocols/rdp
@load base/protocols/smb
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/ssl
@load protocols/http/detect-sqli
@load protocols/conn/vlan-logging
@load policy/protocols/ssl/heartbleed
@load policy/protocols/smb
@load misc/loaded-scripts
@load tuning/defaults
@load misc/scan
@load misc/detect-traceroute
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/http/detect-webapps
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssl/notary
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames


# analysis
@load frameworks/software/windows-version-detection
@load frameworks/software/vulnerable
@load misc/capture-loss
@load misc/known-devices
@load misc/scan

# misc
@load frameworks/dpd/detect-protocols
@load frameworks/communication/listen
@load policy/misc/stats
