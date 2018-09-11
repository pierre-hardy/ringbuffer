// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

#include <iostream>

#include <thread>
#include <chrono>
#include <functional>
#include <atomic>
#include <pthread.h>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/spdy/chromium/spdy_http_utils.h"
#include "net/spdy/core/spdy_header_block.h"
#include "net/tools/quic/quic_simple_client.h"
#include "quic_my_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "url/gurl.h"
#include "quic_my_client_utils.h"

#include "resource_mgr.h"

using namespace net;
using net::CertVerifier;
using net::CTPolicyEnforcer;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using net::ProofVerifier;
using net::ProofVerifierChromium;
using net::QuicStringPiece;
using net::QuicTextUtils;
using net::SpdyHeaderBlock;
using net::TransportSecurityState;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

static int64_t total_size = 0;

//void * operator new(unsigned long size)
//{
//    // 下面两种方法可以达到同样的效果，但下面一种比较好
//    // 因为用下面一种可以保持原有的申请方式一样
//    //void * p = malloc(size);
//    void * p = malloc(size+sizeof(total_size));
//    int64_t s = size;
//    *((int64_t *)p) = s;
//    total_size += size;
//    
//    return (char*)p+sizeof(total_size);
//}
//void operator delete(void * p)
//{
//    int64_t s = *((int64_t *)(((char*)p-sizeof(total_size))));
//    total_size -= s;
//    free(((char*)p-sizeof(total_size)));
//}

extern "C" int64_t get_mem_used() {
    return total_size;
}
//void operator delete [] (void * p)
//{
//    int64_t s = *((int64_t *)(((char*)p-sizeof(total_size))));
//    total_size -= s;
//    free(((char*)p-sizeof(total_size)));
//}

// The IP or hostname the quic client will connect to.
static string FLAGS_host = "";
// The port to connect to.
static int32_t FLAGS_port = 0;
// If set, send a POST with this body.
static string FLAGS_body = "abcdef";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
static string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
static string FLAGS_headers = "";
// Set to true for a quieter output experience.
static bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
static int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
static bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
static bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
static int32_t FLAGS_initial_mtu = 0;

class FakeProofVerifier : public ProofVerifier {
    public:
    net::QuicAsyncStatus VerifyProof(
                                     const string& hostname,
                                     const uint16_t port,
                                     const string& server_config,
                                     net::QuicTransportVersion quic_version,
                                     QuicStringPiece chlo_hash,
                                     const std::vector<string>& certs,
                                     const string& cert_sct,
                                     const string& signature,
                                     const net::ProofVerifyContext* context,
                                     string* error_details,
                                     std::unique_ptr<net::ProofVerifyDetails>* details,
                                     std::unique_ptr<net::ProofVerifierCallback> callback) override {
        return net::QUIC_SUCCESS;
    }
    
    net::QuicAsyncStatus VerifyCertChain(
                                         const std::string& hostname,
                                         const std::vector<std::string>& certs,
                                         const net::ProofVerifyContext* verify_context,
                                         std::string* error_details,
                                         std::unique_ptr<net::ProofVerifyDetails>* verify_details,
                                         std::unique_ptr<net::ProofVerifierCallback> callback) override {
        return net::QUIC_SUCCESS;
    }
};

class Holder {
public:
    std::shared_ptr<net::QuicMySimpleClient> clientInstance;
public:
    Holder(const char *host, int port) {
        this->host = host;
        this->port = port;
    }
    
    void waitConnection() {
        while(waitFlag == -1) {
            usleep(1000*20);
        }
    }
    
    bool isConnectionSuccessed() {
        return waitFlag == 0;
    }

    int failed(int code) {
        waitFlag = 1;
        return code;
    }

    void successed() {
        waitFlag = 0;
    }
    
    string host;
    int port;
private:
    int waitFlag = -1;
};

static int quic_main(int argc, char* argv[], void *holder);
static std::mutex mut_quic_main;

static void *quic_thread(void *holder)
{
    char *argv[] = {
        (char *)"quic_client",
        (char *)"--host=127.0.0.1",
        (char *)"--disable-certificate-verification",
        (char *)"--version_mismatch_ok",
        (char *)"--quic-version=39",
        (char *)"--port=8082",
        (char *)"--v=1",
        (char *)"http://www.google.com.sg",
    };
    {
        ref_holder<Holder> rh(holder);
        if(!rh.get()) {
            return NULL;
        }
        string host = "--host=" + rh.get()->host;
        string port = "--port=" + std::to_string(rh.get()->port);
        argv[1] = (char *)host.c_str();
        argv[5] = (char *)port.c_str();
    }
#ifdef __APPLE__
    pthread_setname_np("quic_main");
#endif
    //禁止两个quic main同时运行
    std::unique_lock<std::mutex> lock(mut_quic_main);
    quic_main(sizeof(argv)/sizeof(argv[0]), argv, holder);
    return NULL;
}

static void destroy_cb(void *connection)
{
    Holder *pHolder = (Holder *)connection;
    delete pHolder;
}


extern "C" void *quic_client_connection_open(const char *host, int port)
{
    Holder *pHolder = new Holder(host, port);
//    std::thread t(quic_thread, pHolder);
    int connection = resource_mgr_create_ctxinfo(pHolder, destroy_cb);
    if(connection == 0) {
        delete pHolder;
        return NULL;
    }

    ref_holder<Holder> rh(connection);
    pthread_t ntid;
    pthread_create(&ntid, NULL, (void *(*)(void * ))quic_thread, (void *)(int64_t)connection);

    rh.get()->waitConnection();
    if(!rh.get()->isConnectionSuccessed()) {
        INFO_PRINT("############# quic connection error\n");
        return NULL;
    }
    return (void *)(int64_t)connection;
}

extern "C" void quic_client_connection_close(void *connection)
{
    ref_holder<Holder> rh(connection);
    if(!rh.get())
        return;
    rh.get()->clientInstance->breakWait();
}

extern "C" int quic_client_connection_read(void *connection, void *buff, int len)
{
    ref_holder<Holder> rh(connection);
    if(!rh.get())
        return -1;
    return rh.get()->clientInstance->ReadData(buff, len);
}

extern "C" int quic_client_connection_write(void *connection, void *buff, int len)
{
    ref_holder<Holder> rh(connection);
    if(!rh.get())
        return -1;
    return rh.get()->clientInstance->WriteData(buff, len);
}

static int unref_and_destroy(void *holder, int code) {
    resource_mgr_unreference_ctxinfo((int)(int64_t)holder);
    resource_mgr_sync_destroy_ctxinfo((int)(int64_t)holder);
    return code;
}

static int quic_main(int argc, char* argv[], void *holder) {
    Holder *pHolder = (Holder *)resource_mgr_reference_ctxinfo((int)(int64_t)holder);
    if(!pHolder)
        return -1;
    base::CommandLine::Init(argc, argv);
    base::CommandLine* line = base::CommandLine::ForCurrentProcess();
    const base::CommandLine::StringVector& urls = line->GetArgs();    

    if (line->HasSwitch("host")) {
        FLAGS_host = line->GetSwitchValueASCII("host");
    }
    if (line->HasSwitch("port")) {
        base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port);
    }
    if (line->HasSwitch("quic-version")) {
        int quic_version;
        if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
                              &quic_version)) {
            FLAGS_quic_version = quic_version;
        }
    }
    if (line->HasSwitch("version_mismatch_ok")) {
        FLAGS_version_mismatch_ok = true;
    }
    
    VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
    << " body: " << FLAGS_body << " headers: " << FLAGS_headers
    << " quiet: " << FLAGS_quiet
    << " quic-version: " << FLAGS_quic_version
    << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
    << " redirect_is_success: " << FLAGS_redirect_is_success
    << " initial_mtu: " << FLAGS_initial_mtu;
    
//    base::AtExitManager exit_manager;
    base::MessageLoopForIO message_loop;
//    SetQuicFlag(&FLAGS_quic_buffered_data_threshold, 1024*1024);
    
    // Determine IP address to connect to from supplied hostname.
    net::QuicIpAddress ip_addr;
    
    GURL url(urls[0]);
    string host = FLAGS_host;
    if (host.empty()) {
        host = url.host();
    }
    int port = FLAGS_port;
    if (port == 0) {
        port = url.EffectiveIntPort();
    }
    if (!ip_addr.FromString(host)) {
        pHolder->failed(1);
        return unref_and_destroy(holder, 1);
    }
    
    string host_port = net::QuicStrCat(ip_addr.ToString(), ":", port);
    VLOG(1) << "Resolved " << host << " to " << host_port << endl;
    
    // Build the client, and try to connect.
    net::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                                net::PRIVACY_MODE_DISABLED);
    net::ParsedQuicVersionVector versions = net::AllSupportedVersions();
    if (FLAGS_quic_version != -1) {
        versions.clear();
        versions.push_back(net::ParsedQuicVersion(
                                                  net::PROTOCOL_QUIC_CRYPTO,
                                                  static_cast<net::QuicTransportVersion>(FLAGS_quic_version)));
    }
    std::unique_ptr<ProofVerifier> proof_verifier;
    if (line->HasSwitch("disable-certificate-verification")) {
        proof_verifier.reset(new FakeProofVerifier());
    } else {
    }
    std::shared_ptr<net::QuicMySimpleClient> client(new net::QuicMySimpleClient(net::QuicSocketAddress(ip_addr, port), server_id,
                                                                                versions, std::move(proof_verifier)));
    client->set_initial_max_packet_length(
                                          FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize);
    if (!client->Initialize()) {
        cerr << "Failed to initialize client." << endl;
        pHolder->failed(1);
        return unref_and_destroy(holder, 1);
    }
    if (!client->Connect()) {
        net::QuicErrorCode error = client->session()->error();
        if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
            cout << "Server talks QUIC, but none of the versions supported by "
            << "this client: " << ParsedQuicVersionVectorToString(versions)
            << endl;
            // Version mismatch is not deemed a failure.
            pHolder->failed(1);
            return unref_and_destroy(holder, 1);
        }
        cerr << "Failed to connect to " << host_port
        << ". Error: " << net::QuicErrorCodeToString(error) << endl;
        pHolder->failed(1);
        return unref_and_destroy(holder, 1);
    }
    cout << "Connected to " << host_port << endl;
    
    // Construct the string body from flags, if provided.
    string body = FLAGS_body;
    
    // Send the request.
    client->SendRequest(body, /*fin=*/false);
    
    pHolder->clientInstance = client;
    INFO_PRINT("###############=set connected=====================\n");
    pHolder->successed();
    client->WaitForResponse();
    
    INFO_PRINT("###############======??====session over====%lld\n", get_mem_used());

    return unref_and_destroy(holder, 0);
}
