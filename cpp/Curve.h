#pragma once

#ifdef _WIN32
#ifdef CURVE_DLL
#ifdef CURVE_LIBRARY_EXPORT
#define CURVE_EXPORT __declspec(dllexport)
#else
#define CURVE_EXPORT __declspec(dllimport)
#endif
#else
#define CURVE_EXPORT
#endif
#else
#define CURVE_EXPORT
#endif

#ifndef _WIN32
#include <stddef.h>
#endif
#include "ByteString.h"
#ifdef __cplusplus
extern "C" {
#endif

CURVE_EXPORT void* curve_auth_create_context(const char* tenant_id, const char* client_id, const char* resource);
CURVE_EXPORT void curve_auth_set_x5c(void* context, bool b);
CURVE_EXPORT void curve_auth_set_secret(void* context, const char* password);
CURVE_EXPORT void curve_auth_set_cert_file(void* context, const char* pfx_file_path, const char* password);
CURVE_EXPORT const char* curve_auth_get_token(void* context, bool force_new);
CURVE_EXPORT void curve_auth_destroy_context(void *context);
CURVE_EXPORT void* curve_auth_create_jwt(const char* tenant_id, const char* client_id, const char* pfx_file_path, const char* password, bool use_x5c);


CURVE_EXPORT void* curve_http_new_get_request(const char* urlstr);
CURVE_EXPORT void* curve_http_new_head_request(const char* urlstr);
CURVE_EXPORT void* curve_http_new_put_request(const char* urlstr, size_t contentSize, const char* data);
CURVE_EXPORT void* curve_http_new_patch_request(const char* urlstr, size_t contentSize, const char* content);
CURVE_EXPORT void* curve_http_new_post_request(const char* urlstr, size_t length, const char* postData);
CURVE_EXPORT void* curve_http_new_delete_request(const char* urlstr);
CURVE_EXPORT void curve_http_request_set_verbose(void* request);
CURVE_EXPORT void curve_http_request_add_header(void* request, const char* header);
CURVE_EXPORT void curve_http_request_set_hdr_payload(void* request, void* payload);
CURVE_EXPORT void curve_http_request_set_body_payload(void* request, void* payload);
CURVE_EXPORT void curve_http_request_set_header_callback(void* request, size_t (*headerCallBack)(const char*, size_t, size_t, void*));
CURVE_EXPORT void curve_http_request_set_writer_callback(void* request, size_t (*writerCallBack)(const char*, size_t, size_t, void*));
CURVE_EXPORT void curve_http_request_set_on_error(void* request, void (*callBack)(const char*, void*));
CURVE_EXPORT void curve_http_request_set_on_complete(void* request, void (*callBack)(void*));
CURVE_EXPORT void* curve_http_create_client(long maxConnections, long connectionCacheSize);
CURVE_EXPORT void curve_http_destroy_client(void* client);
CURVE_EXPORT bool curve_http_queue_request(void* client, void* request);
CURVE_EXPORT void curve_http_download(void* client);
#ifdef __cplusplus
}
#endif
