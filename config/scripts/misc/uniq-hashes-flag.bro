###########################################
# Script to add an extra columns of uniq_hash flag, host and
# peer descr for the uniq hashes that BRO sees in a day.
# fatemabw 10/04/16
###########################################

module Uniq_hashes;

redef record Files::Info += {
    ## Adding a field column of host and uniq_hash to show from where
    ## the file got downloaded and whether seen first time or duplicate.
    host: string &optional &log;
    uniq_hash: bool &optional &log;
    #peer_host: addr &optional &log;
    peer_descr: string &optional &log;
};

global SECONDS_IN_DAY = 60*60*24;
global uniq_hashes: set[string] &synchronized;

function midnight(): time
{
    local now = current_time();
    local dt = time_to_double(now);
    local mn =  double_to_count(dt / SECONDS_IN_DAY) * SECONDS_IN_DAY;
    local mn_EST = mn + 14400.0;
    return double_to_time(mn_EST);
}

function interval_to_midnight(): interval
{
    return midnight() - current_time();
}

event reset_hashes()
{
    uniq_hashes = set();  #I think this is the proper way to clear a set?
}

event file_hash(f: fa_file, kind: string, hash: string)
    {
    #print "file_hash", f$id, kind, hash;
   local peer = get_event_peer();

    #f$info$peer_host = peer$host;
    f$info$peer_descr = peer$descr;

    if(f?$http && f$http?$host)
      f$info$host = f$http$host;

    if(hash in uniq_hashes)
      f$info$uniq_hash = F;

    else
      {
        add uniq_hashes[hash];
        f$info$uniq_hash = T;
      }

    }
event bro_init()
{   #print "current_time", current_time();
    #print "midnight", midnight();
    #print "Time to midnight:", interval_to_midnight();
    schedule interval_to_midnight() { reset_hashes()};
}
