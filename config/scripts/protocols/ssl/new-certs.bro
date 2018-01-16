##! Generate notices when X.509 certificates over SSL/TLS are expired or
##! going to expire soon based on the date and time values stored within the
##! certificate.

@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module SSL;

export {
  redef enum Notice::Type += {
    ## Indicates that a certificate's NotValidBefore date is within
    # the last `notify_when_cert_created_within` time.
    Certificate_Recently_Created
  };

  #const ignore_certificate_list = //

  ## The category of hosts you would like to be notified about which have
  ## certificates that are recently created.  By default, these
  ## notices will be suppressed by the notice framework for 1 day after
  ## a particular certificate has had a notice generated.
  ## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
  const notify_certs_creation = LOCAL_HOSTS &redef;

  ## The time window after a certificate is created that you would like
  ## to start receiving :bro:enum:`SSL::Certificate_Recently_Created` notices.
  const notify_when_cert_created_within = 30days &redef;
}

event ssl_established(c: connection) &priority=3
  {
  # If there are no certificates or we are not interested in the server, just return.
  if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
       ! addr_matches_host(c$id$resp_h, notify_certs_creation) ||
       ! c$ssl$cert_chain[0]?$x509 || ! c$ssl$cert_chain[0]?$sha1 )
    return;

  # TODO: If the certificate is in the whitelist, just return
  #if

  local fuid = c$ssl$cert_chain_fuids[0];
  local cert = c$ssl$cert_chain[0]$x509$certificate;
  local hash = c$ssl$cert_chain[0]$sha1;

  if ( cert$not_valid_before + notify_when_cert_created_within > network_time() )
    NOTICE([$note=Certificate_Recently_Created,
            $conn=c, $suppress_for=1day,
            $msg=fmt("Certificate %s was created for server %s at %T", cert$subject, c$ssl$server_name, cert$not_valid_before),
            $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
            $fuid=fuid]);

  }
