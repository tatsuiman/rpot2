# Copyright (C) 2016, Missouri Cyber Team
# All Rights Reserved
# See the file "LICENSE" in the main distribution directory for details
#
# filename: detect-insecure-protos.bro
#
# This policy provides a framework to detect non-compliant configurations that
# provide services using insecure network protocols. You may whitelist specific
# services and change which hosts are alerted on (defaults to local hosts).
@load base/utils/directions-and-hosts
@load base/utils/strings
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/irc
@load base/protocols/radius
@load base/protocols/pop3

module Compliance;

export {
  #============================#
  # Notice Types               #
  #============================#
  redef enum Notice::Type += {
    Compliance::NonCompliant_Protocol,
  };

  #============================#
  # Configuration variables    #
  #============================#
  # This is a set of protocol analyzers that are labeled as insecure.
  # you can add to this list or take away in other scripts as needed.
  const insecure_protocols: set[Analyzer::Tag] = {
    Analyzer::ANALYZER_FTP,
    Analyzer::ANALYZER_HTTP,
    Analyzer::ANALYZER_IRC,
    Analyzer::ANALYZER_RADIUS,
    # SMTP and SNMP are special cases and may need more refinement
    #Analyzer::ANALYZER_SMTP,
    #Analyzer::ANALYZER_SNMP,
    Analyzer::ANALYZER_POP3,
  } &redef;

  # This allows you to whitelist services by specific hosts
  # The event will check to see if the given protocol is being served
  # by a whitelisted host. If not, it will alert.
  const host_proto_exceptions: table[Analyzer::Tag] of set[addr] = {
    #[Analyzer::ANALYZER_HTTP] = set(127.0.0.1),
  } &redef;

  # Choices are LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
  global alert_on_orig = ALL_HOSTS &redef;
  global alert_on_resp = LOCAL_HOSTS &redef;
}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
{
  # Check to see if this is the direction we care about
  if( ! addr_matches_host(c$id$orig_h, alert_on_orig) ||
      ! addr_matches_host(c$id$resp_h, alert_on_resp) )
      return;

  # Check to see if this is an insecure protocol
  if ( atype in insecure_protocols )
  {
    ## Check to make sure this isn't a whitelisted host/service
    if ( atype !in host_proto_exceptions ||
         c$id$resp_h !in host_proto_exceptions[atype] )
    {
      local message = fmt("%s connected to %s using insecure protocol of %s",
          c$id$orig_h,
          c$id$resp_h,
          join_string_set(c$service, ",") );
      # Generate notice
      NOTICE([$note=Compliance::NonCompliant_Protocol,
              $conn=c,
              $msg=message,
              $identifier=cat(c$id$orig_h,c$id$resp_h,c$service)]);
    }
  }
}
