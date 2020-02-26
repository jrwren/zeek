#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include "SSL.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "Manager.h"
#include "util.h"

#include "events.bif.h"
#include "ssl_pac.h"
#include "tls-handshake_pac.h"

using namespace analyzer::ssl;

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
	{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
	}

SSL_Analyzer::SSL_Analyzer(Connection* c)
: tcp::TCP_ApplicationAnalyzer("SSL", c)
, decrypt_orig {nullptr}, decrypt_not_orig {nullptr}
	{
	interp = new binpac::SSL::SSL_Conn(this);
	handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
	had_gap = false;
	}

SSL_Analyzer::~SSL_Analyzer()
	{
	delete interp;
	delete handshake_interp;
	}

void SSL_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	handshake_interp->FlowEOF(true);
	handshake_interp->FlowEOF(false);
	}

void SSL_Analyzer::EndpointEOF(bool is_orig)
	{
	DecryptProcess *d;
	if ( is_orig )
		d = decrypt_orig.get();
	else
		d = decrypt_not_orig.get();
	if (d!=nullptr) {
		d->Close();
		if (d->exit_status != 0) {
			BifEvent::generate_ssl_tp_fail(this,
				Conn(), d->exit_status);
		}
		auto data = d->Read();
		if (data.get()!=nullptr && *data!="") {
			DBG_LOG(DBG_ANALYZER, "read %lu bytes from tp after closing stdin", data->length());
			DoHTTP(*data, is_orig);
			} else { DBG_LOG(DBG_ANALYZER, "read 0 bytes from tp after closing stdin");}
		}
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	handshake_interp->FlowEOF(is_orig);
	}

void SSL_Analyzer::StartEncryption()
	{
	interp->startEncryption(true);
	interp->startEncryption(false);
	interp->setEstablished();
	}

void SSL_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::SendHandshake(uint16 raw_tls_version, const u_char* begin, const u_char* end, bool orig)
	{
	handshake_interp->set_record_version(raw_tls_version);
	try
		{
		handshake_interp->NewData(orig, begin, end);
		// The way SSL_Conn is split from Handshake_Conn makes this awkward.
		// This does the wrong thing in the case of SSLv2, but that is OK.
		// It is deprecated. https://tools.ietf.org/html/rfc6176
		interp->set_clientrandom( handshake_interp->clientrandom() );
		interp->set_serverrandom( handshake_interp->serverrandom() );
		interp->set_chosen_cipher( handshake_interp->chosen_cipher() );
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void SSL_Analyzer::DoHTTP(std::string data, bool is_orig)
	{
	if ( ! http_active )
		{
		auto ha = analyzer_mgr->InstantiateAnalyzer("HTTP", Conn());
		if ( ha != nullptr )
			{
			AddChildAnalyzer(ha);
			http_active = true;
			} else {
			cerr << "could not instantiate HTTP analyzer" << ha << endl;
			Tag tag = analyzer_mgr->GetComponentTag("HTTP");
			cerr << "got tag:" << &tag << endl;
			}
		}
	if ( http_active )
	try
		{
		DBG_LOG(DBG_ANALYZER,
			"deliverying to child(http analyzer stream %zd bytes starts with %s",
			data.size(), data.substr(0, min(static_cast<size_t>(20), data.size())).c_str());
		ForwardStream(data.size(), reinterpret_cast<const u_char*>(data.c_str()), is_orig);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

pid_t popen2(const char *const argv[], int *in, int *out, int *err)
	{
    int res;
    pid_t pid = 0;
    int inpipefd[2];
    int outpipefd[2];
    int errpipefd[2];
    if(0!=pipe(inpipefd)) {
        perror("allocating pipe for child stdin");
        return -1;
    }
    if(0!=pipe(outpipefd)) {
        close(inpipefd[0]);
        close(inpipefd[1]);
        perror("allocating pipe for child stdout");
        return -1;
    }
    if(0!=pipe(errpipefd)) {
        close(inpipefd[0]);
        close(inpipefd[1]);
        close(outpipefd[0]);
        close(outpipefd[1]);
        perror("allocating pipe for child stderr");
        return -1;
    }
    pid = fork();
    if (0==pid) {
        if (-1==dup2(inpipefd[0], STDIN_FILENO)) {exit(errno);}
        if (-1==dup2(outpipefd[1], STDOUT_FILENO)) {exit(errno);}
        if (-1==dup2(errpipefd[1], STDERR_FILENO)) {exit(errno);}
        close(inpipefd[0]);
        close(inpipefd[1]);
        close(outpipefd[0]);
        close(outpipefd[1]);
        close(errpipefd[0]);
        close(errpipefd[1]);
        execvp(argv[0], (char* const*)argv);
        perror("exec failed");
        exit(1);
    }
    close(inpipefd[0]);
    close(outpipefd[1]);
    close(errpipefd[1]);
    *in = inpipefd[1];
    *out = outpipefd[0];
    *err = errpipefd[0];
    return pid;
	}

template <typename T>
struct hexwrite
	{
    hexwrite(T v_) : v(v_) {}
    T v;
	};

template <typename T>
std::ostream& operator<< (std::ostream& ostr, const hexwrite<T> &fwv)
	{
    return ostr << std::setw(2)<< std::setfill('0')<< std::hex << fwv.v;
	}

size_t writeall(int fd, const char* buf, const size_t len)
	{
	size_t total = 0;
	int bytesleft = len;
	int n;
	while(total<len)
		{
		n = write(fd, buf+total, bytesleft);
		if (n==-1) { break; }
		total +=n;
		bytesleft -=n;
		}
	return n==-1?-1:total;
	}

std::unique_ptr<std::string> SSL_Analyzer::DecryptString(int tlsver, int cs, binpac::bytestring cr, binpac::bytestring sr, bool is_orig, std::string cont)
	{
	try {
		if ( is_orig && decrypt_orig==nullptr) {
			DBG_LOG(DBG_ANALYZER,"creating DecryptProcess for orig");
			decrypt_orig = make_unique<DecryptProcess>(tlsver, cs, cr, sr, true);
			}
		if ( !is_orig && decrypt_not_orig==nullptr) {
			DBG_LOG(DBG_ANALYZER, "creating DecryptProcess for not orig");
			decrypt_not_orig = make_unique<DecryptProcess>(tlsver, cs, cr, sr, false);
			}
		DecryptProcess *d;
		if ( is_orig )
			d = decrypt_orig.get();
		else
			d = decrypt_not_orig.get();
		int n = d->Write(cont);
		DBG_LOG(DBG_ANALYZER, "write %d bytes to tp stdin", n);
		return d->Read();
		}
	catch (PopenFailException& ex) {
		DBG_LOG(DBG_ANALYZER, "%s", ex.what());
		return std::unique_ptr<std::string>();
		}
	}

DecryptProcess::DecryptProcess(int tlsver, int cs, binpac::bytestring cr, binpac::bytestring sr, bool is_orig)
	: inclosed {false} {
	std::ostringstream clientrandom_hex, serverrandom_hex, tlsver_hex;
	auto result = std::unique_ptr<std::string>{new string()};
	// Converting binary (not just ascii) to hex in C++ has surprising edge cases. Use this hexwrite.
	std::copy(cr.begin(), cr.end(), std::ostream_iterator<hexwrite<int>>(clientrandom_hex));
	std::copy(sr.begin(), sr.end(), std::ostream_iterator<hexwrite<int>>(serverrandom_hex));
	tlsver_hex << "0x" << std::hex  << std::setfill('0') << std::setw(4) << tlsver;
	auto crs = clientrandom_hex.str(); // gotta make these temps, don't do it all on one line because
	auto srs = serverrandom_hex.str(); // the string in blah.str().c_str() is immediately deleted.
	auto tvs = tlsver_hex.str();
	const char* clientrandomhex_cstr = crs.c_str();
	const char* serverrandomhex_cstr = srs.c_str();
	const char* tlsverhex_cstr = tvs.c_str();
	int in = 0, out = 0, err = 0;
    int res = 0;
	int n = 0;
	const char *argv[13] = {
        "tp",
        "-tlsver",
        tlsverhex_cstr,
        "-ciphersuite",
        std::to_string(cs).c_str(),
        "-clientrandom",
        clientrandomhex_cstr,
        "-serverrandom",
        serverrandomhex_cstr,
		"-masterkeyfile",
        "tls.keylog",
        is_orig ? "-isclient": nullptr,
        nullptr
	};
	DBG_LOG(DBG_ANALYZER,
		"calling tp to decrypt with tlsver %s client random %s and server random %s",
		tlsverhex_cstr, clientrandomhex_cstr, serverrandomhex_cstr);
	if(0>=(pid = popen2(argv, &in, &out, &err))) {
		throw PopenFailException();
	}
	in_fd = in;
	out_fd = out;
	err_fd = err;
	}

int DecryptProcess::Close() {
	if(!inclosed)
		{
		int r = close(in_fd);
		if (r!=0) {
			char ebuf[256];
			bro_strerror_r(errno, ebuf, sizeof(ebuf));
			DBG_LOG(DBG_ANALYZER, "could not close stdin of tp process %d: %s",
				pid, ebuf);
			}
		inclosed = true;
		}
	// Try to reap zombies, but don't block.
	int es = 0;
	if(0 > waitpid(pid, &es, WNOHANG))
		{
		char ebuf[256];
		bro_strerror_r(errno, ebuf, sizeof(ebuf));
		DBG_LOG(DBG_ANALYZER, "waitpid error pid %d: %s", pid, ebuf);
		}
	else {
		// don't bother with exit_status if the process didn't exit cleanly.
		if (WIFEXITED(es)) {
			exit_status = WEXITSTATUS(es);
		}
	}
	return 0;
}

DecryptProcess::~DecryptProcess() {
	int r;
	if(!inclosed)
		{
		r = close(in_fd);
		if (r!=0) {
			char ebuf[256];
			bro_strerror_r(errno, ebuf, sizeof(ebuf));
			DBG_LOG(DBG_ANALYZER, "could not close stdin of tp process: %s", ebuf);
			}
		}
	r = close(out_fd);
	if (r!=0) {
		char ebuf[256];
		bro_strerror_r(errno, ebuf, sizeof(ebuf));
		DBG_LOG(DBG_ANALYZER, "could not close stdout of tp process: %s", ebuf);
		}
	r = close(err_fd);
	if (r!=0) {
		char ebuf[256];
		bro_strerror_r(errno, ebuf, sizeof(ebuf));
		DBG_LOG(DBG_ANALYZER, "could not close stderr of tp process: %s", ebuf);
		}
	// Kill the child process. It can do nothing for us anymore.
	kill(pid, SIGKILL);
}

int DecryptProcess::Write(std::string cont) {
	int res = writeall(in_fd, cont.c_str(), cont.length());
	if(res==-1) {
		DBG_LOG(DBG_ANALYZER, "error writing to stdin of child process tp");
	}
	return res;
	}

unique_ptr<std::string> DecryptProcess::Read() {
	auto result = make_unique<std::string>();
	char buf[1024*16]; // TLS record max size, not that it matters.
	fd_set rfds;
	struct timeval tv;
	int n;
	int fcnt;
	tv.tv_sec = 0;
	tv.tv_usec = 10000;
	FD_ZERO(&rfds);
	FD_SET(out_fd, &rfds);
	FD_SET(err_fd, &rfds);
	fcnt = select(std::max(out_fd, err_fd)+1, &rfds, NULL, NULL, &tv);
	tv.tv_usec = 0;
	do
		{
		n=0;
		if (fcnt == -1) {
			DBG_LOG(DBG_ANALYZER, "error calling select for tp stdout, stderr");
			return result;
			} else if (fcnt == 0) {
			DBG_LOG(DBG_ANALYZER, "select timed out waiting on stdout, stderr");
			return result;
			}
		if (FD_ISSET(err_fd, &rfds)) {
			DBG_LOG(DBG_ANALYZER, "FD_ISSET err_fd");
			n = read(err_fd, buf, sizeof(buf));
			if (n>0) {
				if (n == sizeof(buf)) {
					n--;
					}
				buf[n] = '\0';
				DBG_LOG(DBG_ANALYZER, "stderr from tp: %s", buf);
				}
			}
		if (FD_ISSET(out_fd, &rfds)) {
			DBG_LOG(DBG_ANALYZER, "reading from tp stdout");
			n = read(out_fd, buf, sizeof(buf));
			if (n == -1) {
				char ebuf[256];
				bro_strerror_r(errno, ebuf, sizeof(ebuf));
				DBG_LOG(DBG_ANALYZER, "error reading from stdout of child tp process: %s", ebuf);
				return result;
				}
			if (n>0)
				result->append(buf, n);
			}
		FD_ZERO(&rfds);
		FD_SET(out_fd, &rfds);
		FD_SET(err_fd, &rfds);
		fcnt = select(std::max(out_fd, err_fd)+1, &rfds, NULL, NULL, &tv);
		} while ( n > 0 );
	return result;
	}