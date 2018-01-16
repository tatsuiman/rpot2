##! Basic POP3 analyzer
# From here: https://github.com/albert-magyar/bro/blob/topic/pop3/scripts/base/protocols/pop3/main.bro

@load base/utils/numbers
@load base/utils/files

module POP3;

export {
    redef enum Log::ID += { LOG };

    ## Set to true to capture passwords from PASS command
    const default_capture_password = F &redef;

    type session_state: enum { AUTHORIZATION, TRANSACTION, UPDATE };


    ## The most significant deviation in this script from the style of
    ## the HTTP and SMTP analyzers is that this record type is NOT used
    ## as a field of the connection struct. In those analyzers, any use
    ## of c$http/c$smtp in an event handler was preceded by a call to
    ## set_state that caused that field to hold the appropriate Info
    ## record instance. Since the persistence of the contents of that
    ## field were restricted to local scope, it has been replaced with
    ## local variables that hold the correct element of the pending queue.
    type CommandInfo: record {
        ts:                      time;
        command:                 string    &optional;
        arg:                     string    &optional;
        status:                  string ;
        msg:                     string    &optional;
        has_client_activity:     bool      &default=F;
    };

    type Info: record {
        ts:                  time                   &log;
        uid:                 string                 &log;
        id:                  conn_id                &log;
        current_request:     count                  &default=0;
        current_response:    count                  &default=0;
        successful_commands: count                  &default=0 &log;
        failed_commands:     count                  &default=0 &log;
        pending:             table[count] of CommandInfo;
        username:            string                 &optional &log;
        password:            string                 &optional &log;
        state:               session_state          &default=AUTHORIZATION;
    };

    ## Event that can be handled to access the POP3 record sent to the logging framework.
    global log_pop3: event(rec: Info);
}

# Add the POP3 state tracking fields to the connection record.
redef record connection += {
	pop3:        Info  &optional;
};

const ports = { 110/tcp };
redef likely_server_ports += { ports };
event bro_init() &priority=5 {
    Log::create_stream(POP3::LOG, [$columns=Info, $ev=log_pop3]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, ports);
}


function new_pop3_command(c: connection): CommandInfo {
    local tmp: CommandInfo;
    tmp$ts=network_time();
    return tmp;
}

function new_pop3_session(c: connection): Info {
    local tmp: Info;
    tmp$ts=network_time();
    tmp$uid=c$uid;
    tmp$id=c$id;
    return tmp;
}

function select_command(c: connection, is_request: bool): CommandInfo {
    if (!c?$pop3) {
        local s: Info;
        c$pop3 = s;
    }
    local current_command: count;
    current_command = (is_request) ? c$pop3$current_request : c$pop3$current_response;
    if (current_command !in c$pop3$pending) {
        c$pop3$pending[current_command] = new_pop3_command(c);
    }
    return c$pop3$pending[current_command];
}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5 {
    if (!c?$pop3)
        c$pop3 = new_pop3_session(c);
    local current_command: CommandInfo;
    current_command = select_command(c, is_orig);
    current_command$has_client_activity = T;
    current_command$command = command;
    current_command$arg = arg;
    ++c$pop3$current_request;
}

function process_command(c: connection, command: CommandInfo) {
    if (command?$command && command$status == "OK") {
        ++c$pop3$successful_commands;
        switch(command$command) {
            case "USER":
                c$pop3$username = command$arg;
                break;
            case "PASS":
                if (default_capture_password)
                    c$pop3$password = command$arg;
                c$pop3$state = TRANSACTION;
                break;
            case "QUIT":
                c$pop3$state = UPDATE;
                break;
        }
    } else if (command?$command && command$status == "ERR") {
        ++c$pop3$failed_commands;
    }
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string) &priority=5 {
    if (!c?$pop3)
        c$pop3 = new_pop3_session(c);
    local current_command: CommandInfo;
    current_command = select_command(c, is_orig);
    current_command$status = cmd;
    current_command$msg = msg;
    process_command(c, current_command);
    if (current_command$has_client_activity)
        ++c$pop3$current_response;
}

event connection_state_remove(c: connection) &priority=-5 {
    if (c?$pop3) {
        Log::write(POP3::LOG, c$pop3);
    }
}
