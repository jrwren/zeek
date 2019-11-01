#ifndef ANALYZER_PROTOCOL_SSL_SSL_H
#define ANALYZER_PROTOCOL_SSL_SSL_H

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"

#include "binpac.h"
#include <memory>
#include <iomanip>
#include <sstream>


namespace binpac { namespace SSL { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace analyzer { namespace ssl {

class DecryptProcess {
public:
	DecryptProcess(int tlsver, int cs, binpac::bytestring cr, binpac::bytestring sr, bool is_orig);
	~DecryptProcess();
	int Write(std::string cont);
	unique_ptr<std::string> Read();
	int Close();
protected:
	bool inclosed;
	int in_fd;
	int out_fd;
	int err_fd;
	pid_t pid;
};

class SSL_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit SSL_Analyzer(Connection* conn);
	~SSL_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;

	void SendHandshake(uint16 raw_tls_version, const u_char* begin, const u_char* end, bool orig);

	// Tell the analyzer that encryption has started.
	void StartEncryption();

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SSL_Analyzer(conn); }

	void DoHTTP(std::string data, bool is_orig);
	unique_ptr<std::string> DecryptString(int tlsver, int cs, binpac::bytestring cr, binpac::bytestring sr, bool is_orig, std::string cont);

protected:
	binpac::SSL::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	bool had_gap;
	bool http_active;
	std::unique_ptr<DecryptProcess> decrypt_orig;
	std::unique_ptr<DecryptProcess> decrypt_not_orig;
};

struct PopenFailException : std::exception {
  const char* what() const noexcept {return "popen failed";}
};

} } // namespace analyzer::* 

#endif
