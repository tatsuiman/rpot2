redef record Conn::Info += {
        peer_descr: string &default="unknown" &log;
};

event connection_state_remove(c: connection){
        c$conn$peer_descr = peer_description;
}
