#define CURVE_DLL
#define CURVE_LIBRARY_EXPORT
#include "Curve.h"
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/conversion.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <curl/curl.h>
#include <glog/logging.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <unordered_map>
#include <uv.h>

namespace curve_http {

enum class HttpVerb {
    GET,
    PUT,
    POST,
    PATCH,
    HEAD,
    DEL,
    CUSTOM
};

void defaultOnError(const char* str, void* obj)
{
    (void)obj;
    LOG(ERROR) << str << "(DefaultErrorHandler";
}

void defaultOnComplete(void *obj)
{
    (void)obj;
    LOG(ERROR) << "completed(default complete handler)";
}

struct WriterCallBack {
    const char* output;
    size_t outputSize;
    size_t index = 0;
    size_t curlCallBack(char* buffer, size_t size, size_t nitems)
    {
        size_t min = outputSize - index;
        if (min > size*nitems)
            min = size*nitems;
        std::memcpy(buffer, output+index, min);
        return min;
    }
};

struct HttpRequest {
    HttpVerb verb { HttpVerb::GET };
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers { nullptr, &curl_slist_free_all };
    std::string url;
    void* hdrPayload{nullptr};
    void* bodyPayload { nullptr };
    size_t (*headerCallBack)(const char*, size_t, size_t, void*) {nullptr};
    size_t (*writerCallBack)(const char*, size_t, size_t, void*) {nullptr};
    void (*onError)(const char*, void*) {defaultOnError};
    void (*onComplete)(void*){defaultOnComplete};
    WriterCallBack wcb;
    std::string postData;
    std::string methodName;
    size_t contentSize { 0 };
    bool isVerbose { false };
};

struct HttpClient : private boost::noncopyable {
    std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> curlMulti { curl_multi_init(), &curl_multi_cleanup };
    std::unique_ptr<uv_loop_t> uvLoop;
    uv_timer_t timer;
    void run();
    void initialize(long maxConnections = 15, long connectionCacheSize = 0);
    bool queueRequest(HttpRequest* request);
};

struct SocketHandlePair {
    uv_poll_t pollHandle;
    curl_socket_t socket;
    CURLM* curlMulti;
};

static void checkMultiInfo(CURLM* multi)
{
    CURLMsg* message = nullptr;
    do {
        int messagesInQ;
        message = curl_multi_info_read(multi, &messagesInQ);
        if (message != nullptr) {
            if (message->msg == CURLMSG_DONE) {
                LOG(INFO) << " queue " << messagesInQ;
                CURL* e = message->easy_handle;
                CURLcode curlCode = message->data.result;
                void* privateVoidPtr = nullptr;
                HttpRequest* request = nullptr;
                auto curlEasyRes = curl_easy_getinfo(e, CURLINFO_PRIVATE, &privateVoidPtr);
                if (CURLE_OK != curlEasyRes) {
                    LOG(ERROR) << "failed to get private ptr";
                } else {
                    request = static_cast<HttpRequest*>(privateVoidPtr);
                }
                char* url = nullptr;
                double totalTime = 0;
                long responseCode;
                curlEasyRes = curl_easy_getinfo(e, CURLINFO_EFFECTIVE_URL, &url);
                if (CURLE_OK != curlEasyRes) {
                    LOG(ERROR) << "failed to get url via curl_easy_getinfo";
                }
                curlEasyRes = curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &responseCode);
                if (CURLE_OK != curlEasyRes) {
                    LOG(ERROR) << "failed to get response code " << url;
                }
                curlEasyRes = curl_easy_getinfo(e, CURLINFO_TOTAL_TIME, &totalTime);
                if (CURLE_OK != curlEasyRes) {
                    LOG(ERROR) << " failed to get totalTime for " << url;
                } else {
                    if (request != nullptr) {
                        if (curlCode == CURLE_OK)
                        {
                            auto callback = request->onComplete;
                            if (callback)
                            {
                                (*callback)(request->hdrPayload);
                            }
                        }
                        else {
                            request->onError(curl_easy_strerror(curlCode), request->hdrPayload);
                        }
                    }
                    LOG(INFO) << url << " took " << totalTime << " seconds and ended with " << curl_easy_strerror(curlCode);
                }
                if (request)
                    delete request;
                curl_multi_remove_handle(multi, e);
                curl_easy_cleanup(e);
            }
        }
    } while (message != nullptr);
}

static SocketHandlePair* createSocketHandle(curl_socket_t s, HttpClient* client)
{
    auto shp = new SocketHandlePair();
    shp->socket = s;
    shp->curlMulti = client->curlMulti.get();
    uv_poll_init_socket(client->uvLoop.get(), &(shp->pollHandle), s);
    shp->pollHandle.data = shp;
    return shp;
}

static void closeHandleCB(uv_handle_t* handle)
{
    auto f = static_cast<SocketHandlePair*>(handle->data);
    delete f;
}

static void deleteSocketHandle(SocketHandlePair* socketHandle)
{
    uv_close((uv_handle_t*)(&socketHandle->pollHandle), closeHandleCB);
}

bool validateAndLog(CURLMcode mcode)
{
    if (mcode == CURLMcode::CURLM_OK) {
        return true;
    } else {
        LOG(ERROR) << mcode << " is not ok." << curl_multi_strerror(mcode);
        return false;
    }
}

void curlPerform(uv_poll_t* req, int status, int events)
{
    (void)status;
    int running_handles;
    int flags = 0;
    SocketHandlePair* context;

    if (events & UV_READABLE)
        flags |= CURL_CSELECT_IN;
    if (events & UV_WRITABLE)
        flags |= CURL_CSELECT_OUT;

    context = (SocketHandlePair*)req->data;

    curl_multi_socket_action(context->curlMulti, context->socket, flags,
        &running_handles);

    checkMultiInfo(context->curlMulti);
}

int socketCallBack(CURL* easy,
    curl_socket_t curlSocket,
    int what,
    void* privateObj, /* private callback pointer */
    void* socketPointer)
{
    (void)easy;
    auto hci = static_cast<HttpClient*>(privateObj);
    SocketHandlePair* socketHandle = nullptr;
    if (socketPointer != nullptr) {
        socketHandle = static_cast<SocketHandlePair*>(socketPointer);
    }

    if (what == CURL_POLL_REMOVE) {
        LOG(INFO) << " removing " << curlSocket;
        if (socketHandle != nullptr) {
            uv_poll_stop(&(socketHandle->pollHandle));
            deleteSocketHandle(socketHandle);
            curl_multi_assign(hci->curlMulti.get(), curlSocket, nullptr);
        }
        return 0;
    }
    if (socketHandle == nullptr) {
        socketHandle = createSocketHandle(curlSocket, hci);
        curl_multi_assign(hci->curlMulti.get(), curlSocket, socketHandle);
    }

    int events = 0;
    switch (what) {
    case CURL_POLL_IN: {
        uv_poll_start(&(socketHandle->pollHandle), (events | UV_READABLE), curlPerform);
        break;
    }
    case CURL_POLL_OUT: {
        uv_poll_start(&(socketHandle->pollHandle), (events | UV_WRITABLE), curlPerform);
        break;
    }
    case CURL_POLL_INOUT: {
        uv_poll_start(&(socketHandle->pollHandle), (events | UV_WRITABLE | UV_READABLE), curlPerform);
        break;
    }
    default:
        break;
    }
    return 0;
}

static void onTimeOut(uv_timer_t* request)
{
    if (request->data == nullptr) {
        DLOG(ERROR) << " empty data in timer call back";
        return;
    }
    auto multi = static_cast<CURLM*>(request->data);
    int runningHandles;
    curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &runningHandles);
    checkMultiInfo(multi);
}

static int curlTimeOutCallBack(CURLM* multi, long timeoutInMs, void* userp)
{
    auto client = static_cast<HttpClient*>(userp);
    if (timeoutInMs < 0) {
        uv_timer_stop(&(client->timer));
        return 0;
    }
    client->timer.data = multi;
    long ts = timeoutInMs > 0 ? timeoutInMs : 1;

    uv_timer_start(&(client->timer), onTimeOut, ts, 0);
    return 0;
}

void HttpClient::initialize(long maxConnections, long connectionCacheSize)
{
    uvLoop.reset(uv_loop_new());
    uv_loop_init(uvLoop.get());

    timer.data = curlMulti.get();
    uv_timer_init(uvLoop.get(), &timer);
    long mc = maxConnections;
    if (mc < 0 || mc > 15)
        mc = 15;
    CURLMcode mcode = curl_multi_setopt(curlMulti.get(), CURLMOPT_SOCKETFUNCTION, socketCallBack);
    mcode = curl_multi_setopt(curlMulti.get(), CURLMOPT_SOCKETDATA, this);
    mcode = curl_multi_setopt(curlMulti.get(), CURLMOPT_TIMERFUNCTION, curlTimeOutCallBack);
    mcode = curl_multi_setopt(curlMulti.get(), CURLMOPT_TIMERDATA, this);
    mcode = curl_multi_setopt(curlMulti.get(), CURLMOPT_MAX_TOTAL_CONNECTIONS, mc);
    if (connectionCacheSize > 0)
        mcode = curl_multi_setopt(curlMulti.get(), CURLMOPT_MAXCONNECTS, connectionCacheSize);
}

size_t curlReaderCallBack(char* buffer, size_t size, size_t nitems, void* obj)
{
    auto wcb = static_cast<WriterCallBack*>(obj);
    return wcb->curlCallBack(buffer, size, nitems);
}

bool HttpClient::queueRequest(HttpRequest* request)
{
    auto curl = curl_easy_init();
    if (curl == nullptr) {
        LOG(FATAL) << "failed to create  easy pointer";
    }    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request->headers.get());
    curl_easy_setopt(curl, CURLOPT_URL, request->url.c_str());
    LOG(INFO) << "using url" << request->url;
    if (request->writerCallBack != nullptr)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, request->writerCallBack);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, request->bodyPayload);
    }
    curl_easy_setopt(curl, CURLOPT_READDATA, &(request->wcb));
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, curlReaderCallBack);
    
    if (request->headerCallBack != nullptr)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, request->headerCallBack);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, request->hdrPayload);
    }
    
    auto httpVerb = request->verb;
    switch (httpVerb) {
    case curve_http::HttpVerb::GET:
        break;
    case curve_http::HttpVerb::PUT:
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, request->contentSize);
        break;
    case curve_http::HttpVerb::POST:
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request->postData.c_str());
        break;
    case curve_http::HttpVerb::PATCH:
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, request->contentSize);
        break;
    case curve_http::HttpVerb::HEAD:
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        break;
    case curve_http::HttpVerb::DEL:
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        break;
    case curve_http::HttpVerb::CUSTOM:
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request->methodName.c_str());
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, request->contentSize);
        break;
    default:
        break;
    }
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "curve");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    if (request->isVerbose) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    curl_easy_setopt(curl, CURLOPT_PRIVATE, request);
    auto rc = curl_multi_add_handle(curlMulti.get(), curl);
    return validateAndLog(rc);
}

void HttpClient::run()
{
    timer.data = curlMulti.get();
    uv_run(uvLoop.get(), UV_RUN_DEFAULT);
}
}

void* curve_http_new_get_request(const char* urlstr)
{
    std::string url = urlstr;
    auto request = new curve_http::HttpRequest();
    request->url = url;
    request->verb = curve_http::HttpVerb::GET;
    return request;
}

void* curve_http_new_head_request(const char* urlstr)
{
    std::string url = urlstr;
    auto request = new curve_http::HttpRequest();
    request->url = url;//curl_escape(url.c_str(), url.size());
    request->verb = curve_http::HttpVerb::GET;
    return request;
}

void* curve_http_new_put_request(const char* urlstr, size_t contentSize, const char* data)
{
    std::string url = urlstr;
    auto request = new curve_http::HttpRequest();
    request->wcb.output = data;
    request->url = url;//curl_escape(url.c_str(), url.size());
    request->verb = curve_http::HttpVerb::PUT;
    request->contentSize = contentSize;
    return request;
}

void* curve_http_new_patch_request(const char* urlstr,  size_t contentSize, const char* content)
{
    std::string url = urlstr;
    auto request = new curve_http::HttpRequest();
    request->wcb.output = content;
    request->url = url;//curl_escape(url.c_str(), url.size());
    request->verb = curve_http::HttpVerb::PATCH;
    request->contentSize = contentSize;
    return request;
}

void* curve_http_new_post_request(const char* urlstr, size_t length, const char* postData)
{
    std::string url = urlstr;
    auto request = new curve_http::HttpRequest();
    request->url = url; //curl_escape(url.c_str(), url.size());
    request->verb = curve_http::HttpVerb::POST;
    request->postData = std::string{postData, length};
    request->contentSize = length;
    return request;
}

void* curve_http_new_delete_request(const char* urlstr )
{
    std::string url = urlstr;
    auto request = new curve_http::HttpRequest();
    request->url = url;//curl_escape(url.c_str(), url.size());
    request->verb = curve_http::HttpVerb::DEL;
    return request;
}

void curve_http_request_set_verbose(void* request)
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->isVerbose = true;
}

void curve_http_request_add_header(void* request, const char* header)
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    curl_slist_append(req->headers.get(), header);
}

void curve_http_request_set_hdr_payload(void* request, void* payload)
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->hdrPayload = payload;
}

void curve_http_request_set_body_payload(void* request, void* payload)
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->bodyPayload = payload;
}

void curve_http_request_set_header_callback(void* request, size_t (*headerCallBack)(const char*, size_t, size_t, void*))
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->headerCallBack = headerCallBack;
}

void curve_http_request_set_writer_callback(void* request, size_t (*writerCallBack)(const char*, size_t, size_t, void*))
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->writerCallBack = writerCallBack;
}

void curve_http_request_set_on_error(void* request, void (*callBack)(const char*, void*))
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->onError = callBack;
}

void curve_http_request_set_on_complete(void* request, void (*callBack)(void*))
{
    auto req = static_cast<curve_http::HttpRequest*>(request);
    req->onComplete = callBack;
}

void* curve_http_create_client(long maxConnections, long connectionCacheSize)
{
    auto client = new curve_http::HttpClient();
    client->initialize(maxConnections, connectionCacheSize);
    return client;
}

void curve_http_destroy_client(void* client)
{
    auto httpClient = static_cast<curve_http::HttpClient*>(client);
    delete httpClient;
}

bool curve_http_queue_request(void* client, void* request)
{
    auto httpClient = static_cast<curve_http::HttpClient*>(client);
    auto req = static_cast<curve_http::HttpRequest*>(request);
    return httpClient->queueRequest(req);
}

void curve_http_download(void* client)
{
    auto httpClient = static_cast<curve_http::HttpClient*>(client);
    httpClient->run();
}


