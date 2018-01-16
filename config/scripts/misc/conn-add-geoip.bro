# Copyright (C) 2016, Missouri Cyber Team
# All Rights Reserved
# See the file "LICENSE" in the main distribution directory for details

##! Add geo_location for the originator and responder of a connection
##! to the connection logs.

module Conn;

export
{
  redef record Conn::Info +=
  {
    orig_location: string &optional &log;
    resp_location: string &optional &log;
    orig_country_code: string &optional &log;
    resp_country_code: string &optional &log;
    orig_asn: count &log &optional;
    resp_asn: count &log &optional;
  };
}

event connection_state_remove(c: connection)
{
  local orig_loc = lookup_location(c$id$orig_h);
  if (orig_loc?$longitude && orig_loc?$latitude)
    c$conn$orig_location= cat(orig_loc$latitude,",",orig_loc$longitude);
  local orig_ccode = lookup_location(c$id$orig_h);
  if (orig_ccode?$country_code)
    c$conn$orig_country_code= cat(orig_ccode$country_code);
  c$conn$orig_asn= lookup_asn(c$id$orig_h);
  local resp_loc = lookup_location(c$id$resp_h);
  if (resp_loc?$longitude && resp_loc?$latitude)
    c$conn$resp_location= cat(resp_loc$latitude,",",resp_loc$longitude);
  local resp_ccode = lookup_location(c$id$resp_h);
  if (resp_ccode?$country_code)
    c$conn$resp_country_code= cat(resp_ccode$country_code);
  c$conn$resp_asn= lookup_asn(c$id$resp_h);
}

export
{
  redef record Conn::Info +=
  {
    orig_location: string &optional &log;
    resp_location: string &optional &log;
  };
}

event connection_state_remove(c: connection)
{
  local orig_loc = lookup_location(c$id$orig_h);
  if (orig_loc?$longitude && orig_loc?$latitude)
    c$conn$orig_location= cat(orig_loc$latitude,",",orig_loc$longitude);
  local resp_loc = lookup_location(c$id$resp_h);
  if (resp_loc?$longitude && resp_loc?$latitude)
    c$conn$resp_location= cat(resp_loc$latitude,",",resp_loc$longitude);
}
