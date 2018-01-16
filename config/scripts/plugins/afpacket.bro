# Workaround for AF_Packet plugin across multiple interfaces
# See https://bro-tracker.atlassian.net/browse/BIT-1747 for more info
@load scripts/rock/plugins/afpacket
redef AF_Packet::fanout_id = strcmp(getenv("fanout_id"),"") == 0 ? 0 : to_count(getenv("fanout_id"));
