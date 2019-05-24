	function proc_server_hello(
					version : uint16,
					server_random : bytestring,
					session_id : uint8[],
					cipher_suites16 : uint16[],
					cipher_suites24 : uint24[],
					comp_method : uint8) : bool
		%{
		if ( ! version_ok(version) )
			{
			bro_analyzer()->ProtocolViolation(fmt("unsupported server SSL version 0x%04x", version));
			bro_analyzer()->SetSkip(true);
			}

// This function is included in both Handshake_Conn AND SSL_Conn very confusing.
// The SSL_Conn version is called only when SSLv2 is used.
		// I do not know why, but I can't use std::move here.
		//serverrandom_ = std::move(server_random);
		serverrandom_.init(server_random.data(), server_random.length());

		if ( ssl_server_hello )
			{
			vector<int>* ciphers = new vector<int>();

			if ( cipher_suites16 )
				std::copy(cipher_suites16->begin(), cipher_suites16->end(), std::back_inserter(*ciphers));
			else
				std::transform(cipher_suites24->begin(), cipher_suites24->end(), std::back_inserter(*ciphers), to_int());

			BifEvent::generate_ssl_server_hello(bro_analyzer(),
							bro_analyzer()->Conn(),
							version, record_version(), new StringVal(server_random.length(),
							(const char*) server_random.data()),
							to_string_val(session_id),
							ciphers->size()==0 ? 0 : ciphers->at(0), comp_method);

			delete ciphers;
			}

		return true;
		%}
