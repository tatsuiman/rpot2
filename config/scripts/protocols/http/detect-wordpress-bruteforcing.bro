# Detect hosts that may be bruteforcing WordPress
# Josh Liburdi 2014-04-14

@load base/frameworks/sumstats
@load base/frameworks/notice

module HTTP;

export {

    redef enum Notice::Type += {
        WordPress_Bruteforcing
    };

    # Threshold to cross before a host is determined to potentially be bruteforcing WordPress
    const wp_bf_threshold: double = 10 &redef;
    # The amount of time to watch for bruteforce activity
    const wp_bf_interval = 20 mins &redef;
}

event http_reply (c: connection, version: string, code: count, reason: string)
  {
  # wp-login.php uses POST variable by default, but can be configured for GET variable
  # TODO Verify if .* is implied for type pattern, necessity of/efficiency of string match before regex
  if ( code == 200 && c$http?$method && c$http?$uri && c$http?$host 
        && ( (c$http$method == "POST" && "wp-login.php" in c$http$uri && /.*wp-login.php$/ in c$http$uri)
        || (c$http$method == "GET" && "wp-login.php" in c$http$uri && /.*log=.*&pwd=.*/ in c$http$uri) ) )
    SumStats::observe("http.wp_bf", [$host=c$id$orig_h, $str=c$http$host], [$str=c$http$uri]);
  }

event bro_init()
  {
  local r1: SumStats::Reducer = [$stream="http.wp_bf", $apply=set(SumStats::UNIQUE)];
  SumStats::create([$name="detect-wordpress-bruteforcing",
                    $epoch=wp_bf_interval,
                    $reducers=set(r1),
                    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["http.wp_bf"]$num+0.0;
                          },
                    $threshold=wp_bf_threshold,
                    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local r = result["http.wp_bf"];
                          local dur = duration_to_mins_secs(r$end-r$begin);
                          local message = fmt("%s had %d failed logins at %s in %s", key$host, r$num, key$str, dur);
                          NOTICE([$note=WordPress_Bruteforcing,
                                  $src=key$host,
                                  $msg=message,
                                  $identifier=key$str]);
                          }]);
  }
