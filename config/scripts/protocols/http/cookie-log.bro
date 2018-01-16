module Cookie;

export {
  # The fully resolve name for this will be LocationExtract::LOG
  redef enum Log::ID += { LOG };
  type Info: record {
    ts:     time    &log;
    uid:    string &log;
    id:     conn_id  &log;
    cookie: string &log;
    cookie_unesc: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Cookie::LOG, [$columns=Info]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5 {
  if ( is_orig && name == "COOKIE") {
    local unesc_cookie = unescape_URI(value);
    local log_rec: Cookie::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $cookie=value, $cookie_unesc=unesc_cookie];
    Log::write(Cookie::LOG, log_rec);
  }
}
