##! This script reassembles full HTTP bodies and raises an event with the
##! complete contents.

module HTTP;

export {
    redef record Info += {
       body: string &optional;
       reassemble_body: bool &default=F;
    };

    ## Flag that indicates whether to hook request bodies.
    const hook_request_bodies = F &redef;

    ## Flag that indicates whether to hook reply bodies.
    const hook_reply_bodies = T &redef;

    ## The pattern applies 
    const hook_host_pattern = /.*/ &redef;

    ## Do not buffer more than this amount of bytes per HTTP message.
    const max_body_size = 50000000;
}

## Users write a handler for this event to process the current HTTP body.
event http_body_complete(c: connection) &priority=-5
    {
    delete c$http$body;
    }

event http_begin_entity(c: connection, is_orig: bool)
    {
    if ( (is_orig && ! hook_request_bodies) ||
         (! is_orig && ! hook_reply_bodies) )
        return;

    if ( hook_host_pattern !in c$http$host )
        return;

    c$http$body = "";
    c$http$reassemble_body = T;
    }

event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
    {
    if ( ! c$http?$body )
        return;

    c$http$body += data;

    if ( c$http$response_body_len < max_body_size )
        return;

    c$http$reassemble_body = F;
    event http_body_complete(c);
    }

event http_end_entity(c: connection, is_orig: bool)
    {
    if ( ! c$http?$body )
        return;

    c$http$reassemble_body = F;
    event http_body_complete(c);
    }
