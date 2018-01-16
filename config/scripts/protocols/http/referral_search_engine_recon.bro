module ReferralSearchEngineRecon;

export {

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:       time &log;
        uid:      string &log;
        srcip:    addr &log;
        dstip:    addr &log;
        msg:      string &log;
        referer:  string  &log;
        };

    const search_engines: set[string] = { "baidu.com", "rollyo.com", "duckduckgo.com", "ask.com", "teoma.com", "gigablast.com", "scrubtheweb.com", "yippy.com", "lycos.com",
                                         "search.aol.com", "kosmix.com", "sogou.com", "youdao.com", "yebol.com", "yandex.ru", "abacho.de", "hakia.com", "lexxe.com", "excite.com",
                                         "chacha.com", "earthfrisk.org", "oneriot.com", "yolink.com/search", "dogpile.com", "hotbot.com", "info.com", "ixquick.com", 
                                         "ws.copernic.com", "metacrawler.com", "turbo10.com/search", "webcrawler.com", "deeperweb.com", "leapfish.com", "google.com.tr",
                                         "google.fr", "google.co.uk", "google.de", "google.it", "google.co.in", "google.es", "google.ca", "google.com.vn", "google.gr", 
                                         "google.com.br", "google.co.id", "google.com.mx", "google.com.ar", "google.org", "google.com.eg", "google.co.jp", "google.com.tw",
                                         "google.ru", "google.co.ma", "google.pl", "google.com.au", "google.com.co", "google.ae", "google.fi", "google.dz", "google.com.hk",
                                         "google.bg", "google.com.my", "google.pt", "google.ch", "google.co.ve", "google.cl", "google.nl", "google.ro", "google.com.ua", 
                                         "google.be", "google.com.pk", "google.hr", "google.co.za", "google.at", "google.com.ec", "google.com.pe", "google.co.th", "google.rs", 
                                         "google.com.sa", "google.cn", "google.lk", "google.se", "google.com.do", "google.sk", "google.co.hu", "google.co.il", "google.cz", 
                                         "google.lt", "google.ie", "google.com.uy", "google.co.ke", "google.com.ng", "google.co.nz", "google.com.sg", "google.si", "google.dk",
                                         "google.no", "google.co.cr", "google.jo", "google.com.ph", "google.mn", "google.iq", "google.com.sv", "google.com.bd", "google.com.pr",
                                         "google.az", "google.cm", "google.com.gt", "google.co.kr", "google.kz", "google.tn", "google.ci", "google.com.cy", "google.ba", 
                                         "google.com.ly", "google.com", "bing.com", "yahoo.com", "lexisnexis.com", "nexis.com", "dailylife.com", "webcache.googleusercontent.com", } &redef;

    const search_social: set[string] = { "linkedin.com", "wink.com", "facebook.com", "twitter.com", } &redef;

                                        #yahoo              google              bing                   yahoo (old)    baidu   gigablast youdao          yandex
    const cache_strings: set[string] = { "search/srpcache?", "search?q=cache:", "cache.aspx?q=cache", "search/cache?", "c?m=", "get?q=", "cache?docid=", "yandbtm?url=", } &redef;

    const search_operators: set[string] = { "site:", "intitle:", "inanchor:", "filetype:", "url:", "intext:", "contains:", "inbody:", "ip:", "loc:", "location:", "hostname:", 
                                           "inlink:", "last:", "host:", "zone:", "dfi:", "site=", "inurl=", "intitle=", "inanchor=", "filetype=", "intext=", "contains=", 
                                           "inbody=", "ip=", "loc=", "location=", "hostname=", "inlink=", "last=", "host=", "zone=", "dfi=", "fieldcontente=on", "fieldtitle=on", 
                                           "sitequery=", "domain=", "domain:", "site%3A", "inurl%3A", "inanchor%3A", "filetype%3A", "intext%3A", "contains%3A", "inbody%3A",
                                           "ip%3A", "loc%3A", "location%3A", "hostname%3A", "inlink%3A", "last%3A", "host%3A", "zone%3A", "dfi%3A", "site%3D", "intitle%3D",
                                           "inanchor%3D", "filetype%3D", "intext%3D", "contains%3D", "inbody%3D", "ip%3D", "loc%3D", "location%3D", "hostname%3D",
                                           "inlink%3D", "last%3D", "host%3D", "zone%3D", "dfi%3D", } &redef;

    const search_keywords: set[string] = {} &redef;
}


event bro_init()
    {
    Log::create_stream(ReferralSearchEngineRecon::LOG, [$columns=Info]);
    }


event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig ) # client headers
        return;

    if ( name == "REFERER" )
        {
        if (Site::is_local_addr(c$id$orig_h) && !Site::is_local_addr(c$id$resp_h))
            {
            for ( se in search_engines )
                {
                local log: Info;
                if ( se in value )
                    {
                    for ( k in search_keywords )
                        {
                        if ( k in value )
                            {
                            log = [$ts=c$start_time,
                                   $msg=fmt("Search Engine: %s Keyword: %s", se, k),
                                   $uid=c$uid, 
                                   $srcip=c$id$orig_h,
                                   $dstip=c$id$resp_h,
                                   $referer=(value == "" ? "NONE" : value)];
                            Log::write(ReferralSearchEngineRecon::LOG, log);
                            }
                        }
                    for ( cs in cache_strings )
                        {
                        if ( cs in value )
                            {
                            log = [$ts=c$start_time,
                                   $msg=fmt("Search Engine: %s Cached: %s", se, cs),
                                   $uid=c$uid, 
                                   $srcip=c$id$orig_h,
                                   $dstip=c$id$resp_h,
                                   $referer=(value == "" ? "NONE" : value)];
                            Log::write(ReferralSearchEngineRecon::LOG, log);
                            return;
                            }
                        }
                    for ( so in search_operators )
                        {
                        if ( so in value )
                            {
                            log = [$ts=c$start_time,
                                   $msg=fmt("Search Engine: %s Operator: %s", se, so),
                                   $uid=c$uid, 
                                   $srcip=c$id$orig_h,
                                   $dstip=c$id$resp_h,
                                   $referer=(value == "" ? "NONE" : value)];
                            Log::write(ReferralSearchEngineRecon::LOG, log);
                            return;
                            }
                        } 
                    log = [$ts=c$start_time,
                           $msg=fmt("Search Engine: %s", se),
                           $uid=c$uid, 
                           $srcip=c$id$orig_h,
                           $dstip=c$id$resp_h,
                           $referer=(value == "" ? "NONE" : value)];
                    Log::write(ReferralSearchEngineRecon::LOG, log);
                    }
                }
            }
        }
    }

