###############################
# Script to log the TLS
# Clients in TLSfingerprint.log
# Courtesy by: Seth Hall
###############################

@load site/tlsfp_db

module TLSFP;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called TLSFP::Info.
    type Info: record {
        c_ts: time &log;
        conn_uid: string &log;
        c_id: conn_id &log;
        c_history: string &log;
        TLSclient: string &log;
        TLSversion: string &log;
        };
}

type TLSFPStorage: record {
        extensions: string &default="";
        e_curves: string &default="";
        sig_alg: string &default="";
        ec_point_fmt: string &default="";
        TLSclient: string &default="";
};

redef record connection += {
        tlsfp: TLSFPStorage &optional;
};

event bro_init()
    {
    # Create the logging stream.
    Log::create_stream(LOG, [$columns=Info, $path="TLSfingerprint"]);
    }

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
        {
        if ( ! c?$tlsfp )
                c$tlsfp=TLSFPStorage();

        local realval = "";
        c$tlsfp$extensions = c$tlsfp$extensions+cat(code);

        if ( code == 10 )
                {
                realval = val[2:];
                c$tlsfp$e_curves = realval;
                }
        else if ( code == 11 )
                {
                realval = val[1:];
                c$tlsfp$ec_point_fmt = realval;
                }
        else if ( code == 13 )
                {
                realval = val[2:];
                c$tlsfp$sig_alg = realval;
                }
        }

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
        {
        if ( ! c?$tlsfp )
                return;

        #ciphersuite_len = |ciphers|*2;
        #print fmt("length of cipher suite: %s",|ciphers|*2);

        local h = md5_hash_init();
        md5_hash_update(h, cat(version));

        for ( i in ciphers )
                {
                md5_hash_update(h, cat(ciphers[i]));
                }

        md5_hash_update(h, c$tlsfp$extensions);
        md5_hash_update(h, c$tlsfp$e_curves);
        md5_hash_update(h, c$tlsfp$sig_alg);
        md5_hash_update(h, c$tlsfp$ec_point_fmt);
        local hash = md5_hash_finish(h);

        if ( hash in TLSFingerprinting::database )
                { c$tlsfp$TLSclient = TLSFingerprinting::database[hash];
                  local version_str=SSL::version_strings[version];
                  local rec: TLSFP::Info = [$c_ts=c$ssl$ts, $conn_uid=c$uid, $c_id=c$id , $c_history=c$history, $TLSclient=c$tlsfp$TLSclient, $TLSversion=version_str];
                  Log::write( TLSFP::LOG, rec);
                  return;
                }

        }
