
redef record HTTP::Info += {
	post_body: string &optional &log;
};

redef record fa_file += {
	http_log: HTTP::Info &optional;
};

event http_get_post_body(f: fa_file, data: string)
	{
	if ( ! f$http_log?$post_body )
		f$http_log$post_body = data;
	else 
		f$http_log$post_body = f$http_log$post_body + data;
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f$source == "HTTP" && is_orig &&
	     c$http$method == "POST" )
		{
		#Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
		f$http_log = c$http;
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=http_get_post_body]);
		}
	}