#define CURVE_DLL
#define CURVE_LIBRARY_EXPORT
#include "Curve.h"
#include <chrono>
#include <curl/curl.h>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <string>

namespace curve_auth {

std::string jwt(const std::string& tenant_id, const std::string& client_id, const char* pfx_file_path, const char* password, bool use_x5c);

struct AuthorizatonContext {
    std::string tenantId;
    std::string clientId;
    std::string resource;
    std::string pfxFilePath;
    std::string pfxPassword;
    std::string clientSecret;
    std::string token;
    bool x5c { false };
    std::chrono::system_clock::time_point time { std::chrono::system_clock::now() };
    std::string jwToken() const
    {
        return jwt(tenantId, clientId, pfxFilePath.c_str(), pfxPassword.c_str(), x5c);
    }
};

struct auth_token {
    std::string token;
    std::string expiry;
};

size_t authHeaderCallBack(char* buffer, size_t size, size_t nitems, void* stream)
{
    rapidjson::Document document;
    document.Parse(buffer, size * nitems);
    auto authContext = static_cast<AuthorizatonContext*>(stream);

    if (document.HasMember("access_token")) {
        authContext->token = document["access_token"].GetString();
        if (document.HasMember("expires_in")) {
            uint32_t secondsToExpiry = 1800; // setting a sane default time
            if (document["expires_in"].IsInt()) {
                secondsToExpiry = document["expires_in"].GetInt();
            } else if (document["expires_in"].IsString()) {
                secondsToExpiry = std::stoul(document["expires_in"].GetString());
            }
            auto now = std::chrono::system_clock::now();
            now += std::chrono::seconds(secondsToExpiry);
            authContext->time = now;
        }
    } else {
        authContext->token = "";
        authContext->time = std::chrono::system_clock::now();
    }

    return size * nitems;
}

bool GetTokenClientSecret(AuthorizatonContext& context)
{
    std::string resource = context.resource;
    std::string url = "https://login.microsoftonline.com/";
    url.append(context.tenantId);
    url.append("/oauth2/token");
    std::string postData = "grant_type=client_credentials&client_id=";
    postData.append(context.clientId);
    postData.append("&client_secret=");
    postData.append(context.clientSecret);
    postData.append("&resource=");
    postData.append(context.resource);

    CURL* curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, authHeaderCallBack);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, &context);
    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        long responseCode;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
        std::cerr << "Encountered error getting Token " << res << ' ' << responseCode;
        return false;
    }
    curl_easy_cleanup(curl);
    return true;
}

bool GetToken(AuthorizatonContext& context)
{
    std::string url = "https://login.microsoftonline.com/";
    url.append(context.tenantId);
    url.append("/oauth2/token");
    std::string postData = "resource=";
    postData.append(context.resource);
    postData.append("&client_id=");
    postData.append(context.clientId);
    postData.append("&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
    postData.append("&client_assertion=");
    postData.append(context.jwToken());
    postData.append("&grant_type=client_credentials");
    CURL* curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, authHeaderCallBack);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, &context);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        long responseCode;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
        std::cerr << "Encountered error getting Token " << res << ' ' << responseCode;
        return false;
    }
    curl_easy_cleanup(curl);
    return true;
}
}

void* curve_auth_create_context(const char* tenant_id, const char* client_id, const char* resource)
{
    auto authContext = new curve_auth::AuthorizatonContext();
    authContext->clientId = client_id;
    authContext->tenantId = tenant_id;
    authContext->resource = resource;
    authContext->token = "";
    return authContext;
}

void curve_auth_set_secret(void* context, const char* password)
{
    auto authContext = static_cast<curve_auth::AuthorizatonContext*>(context);
    authContext->clientSecret = password;
    authContext->token = "";
}

void curve_auth_set_cert_file(void* context, const char* pfx_file_path, const char* password)
{
    auto authContext = static_cast<curve_auth::AuthorizatonContext*>(context);
    authContext->pfxFilePath = pfx_file_path;
    authContext->pfxPassword = password;
    authContext->clientSecret.clear();
    authContext->token = "";
}

void curve_auth_destroy_context(void* context)
{
    auto authContext = static_cast<curve_auth::AuthorizatonContext*>(context);
    delete authContext;
}

const char* curve_auth_get_token(void* context, bool force_new)
{
    auto authContext = static_cast<curve_auth::AuthorizatonContext*>(context);
    if (!force_new && authContext->token.size() > 0) {
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(authContext->time - now);
        if (duration.count() > 20) {
            return authContext->token.c_str();
        }
    }
    if (authContext->pfxFilePath.size() > 0) {
        if (curve_auth::GetToken(*authContext)) {
            return authContext->token.c_str();
        }
    } else if (authContext->clientSecret.size() > 0) {
        if (curve_auth::GetTokenClientSecret(*authContext)) {
            return authContext->token.c_str();
        }
    }
    return "";
}

void curve_auth_set_x5c(void* context, bool b)
{
    auto authContext = static_cast<curve_auth::AuthorizatonContext*>(context);
    authContext->x5c = b;
}

void* curve_auth_create_jwt(const char* tenant_id, const char* client_id, const char* pfx_file_path, const char* password, bool use_x5c)
{
    auto jwt = new std::string(curve_auth::jwt(tenant_id, client_id, pfx_file_path, password, use_x5c));
    return jwt;
}

void curve_auth_destroy_jwt(void* ptr)
{
    auto jwt = static_cast<std::string*>(ptr);
    delete jwt;
}
