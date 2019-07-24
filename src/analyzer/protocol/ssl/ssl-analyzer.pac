# Analyzer for SSL (Bro-specific part).

refine connection SSL_Conn += {

	%include proc-client-hello.pac
	%include proc-server-hello.pac
	%include proc-certificate.pac

	function proc_v2_certificate(is_orig: bool, cert : bytestring) : bool
		%{
		vector<bytestring>* cert_list = new vector<bytestring>(1,cert);
		bool ret = proc_certificate(is_orig, cert_list);
		delete cert_list;
		return ret;
		%}


	function proc_v2_client_master_key(rec: SSLRecord, cipher_kind: int) : bool
		%{
		BifEvent::generate_ssl_established(bro_analyzer(),
				bro_analyzer()->Conn());

		return true;
		%}

	function proc_handshake(rec: SSLRecord, data: bytestring, is_orig: bool) : bool
		%{
		bro_analyzer()->SendHandshake(${rec.raw_tls_version}, data.begin(), data.end(), is_orig);
		return true;
		%}

	function wat_ciphertext_record(rec : SSLRecord, cont: bytestring) : bool
		%{
		DBG_LOG(DBG_ANALYZER, "wat_ciphertext_record w/ content type:%x", ${rec.content_type});
		// If TLS App Data, then decrypt & send to HTTP
		if ( ${rec.content_type} == 0x17 )
			{
			std::stringstream input;
			// uint8 is a char alias so these insertions are as raw char, not as formatted ints.
			input << ${rec.head0} << ${rec.head1} << ${rec.head2} << ${rec.head3} << ${rec.head4} << std_str(cont);
			#if DEBUG
			std::ostringstream clientrandom_hex;
			clientrandom_hex << std::hex  << std::setfill('0') << std::setw(2);
			std::copy(clientrandom_.begin(), clientrandom_.end(), std::ostream_iterator<int>(clientrandom_hex));
			auto tmp = clientrandom_hex.str();
			DBG_LOG(DBG_ANALYZER, "Calling DecryptString with clientrandom %s", tmp.c_str());
			#endif
			auto data = bro_analyzer()->DecryptString(${rec.raw_tls_version}, chosen_cipher_, clientrandom_, serverrandom_, ${rec.is_orig}, input.str());
			if ( data.get() != nullptr && *data != "" )
				{
				DBG_LOG(DBG_ANALYZER, "DecryptString got %s", data->c_str());
				bro_analyzer()->DoHTTP(*data, ${rec.is_orig});
				} else {
				DBG_LOG(DBG_ANALYZER, "DecryptString got null or empty");
				}
			}
		return true;
		%}
};

refine typeattr V2Error += &let {
	proc : bool = $context.connection.proc_alert(rec, -1, error_code);
};


refine typeattr V2ClientHello += &let {
	proc : bool = $context.connection.proc_client_hello(client_version,
				challenge, session_id, 0, ciphers, 0);
};

refine typeattr V2ServerHello += &let {
	check_v2 : bool = $context.connection.proc_check_v2_server_hello_version(server_version);

	proc : bool = $context.connection.proc_server_hello(server_version,
				conn_id_data, 0, 0, ciphers, 0) &requires(check_v2) &if(check_v2 == true);

	cert : bool = $context.connection.proc_v2_certificate(rec.is_orig, cert_data)
		&requires(proc) &requires(check_v2) &if(check_v2 == true);
};

refine typeattr V2ClientMasterKey += &let {
	proc : bool = $context.connection.proc_v2_client_master_key(rec, cipher_kind);
};

refine typeattr Handshake += &let {
	proc : bool = $context.connection.proc_handshake(rec, data, rec.is_orig);
};

refine typeattr CiphertextRecord += &let {
	wat : bool = $context.connection.wat_ciphertext_record(rec, cont);
};
