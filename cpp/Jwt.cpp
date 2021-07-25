#include <iostream>
#include <set>
#include <chrono>
#include <memory>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <sstream>
#include <string>
#include <array>
#include <chrono>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/random_generator.hpp>
#include <openssl/safestack.h>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#pragma comment(lib, "BCrypt.lib")

namespace curve_auth {

    // TODO: moving to base64 of openssl library instead of homegrown version
    std::string toGenericBase64(const std::array<char, 64> & alphabet, const std::string& fill, const char* input, size_t size) {
        std::stringstream encoded;
        size_t padding = size - size % 3;
        for (size_t i = 0; i < padding;) {
            uint32_t octet_a = (unsigned char)input[i++];
            uint32_t octet_b = (unsigned char)input[i++];
            uint32_t octet_c = (unsigned char)input[i++];

            uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

            encoded << alphabet[(triple >> 3 * 6) & 0x3F];
            encoded << alphabet[(triple >> 2 * 6) & 0x3F];
            encoded << alphabet[(triple >> 1 * 6) & 0x3F];
            encoded << alphabet[(triple >> 0 * 6) & 0x3F];
        }

        if (padding == size)
            return encoded.str();

        size_t mod = size % 3;

        uint32_t octet_a = padding < size ? (unsigned char)input[padding++] : 0;
        uint32_t octet_b = padding < size ? (unsigned char)input[padding++] : 0;
        uint32_t octet_c = padding < size ? (unsigned char)input[padding++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        switch (mod) {
        case 1:
            encoded << alphabet[(triple >> 3 * 6) & 0x3F];
            encoded << alphabet[(triple >> 2 * 6) & 0x3F];
            encoded << fill;
            encoded << fill;

            break;
        case 2:
            encoded << alphabet[(triple >> 3 * 6) & 0x3F];
            encoded << alphabet[(triple >> 2 * 6) & 0x3F];
            encoded << alphabet[(triple >> 1 * 6) & 0x3F];
            encoded << fill;
            break;
        default:
            break;
        }

        return encoded.str();
    }


    std::string toBase64Url(std::string input) {
        std::array<char, 64> alphabet = {
                         {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                          'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                          'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                          'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'} };
        std::string fill = "";
        return toGenericBase64(alphabet, fill, input.c_str(), input.size());
    }

    std::string toBase64(std::string input) {
        std::string fill = "=";
        std::array<char, 64> alphabet = {
                         {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                          'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                          'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                          'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'} };
        return toGenericBase64(alphabet, fill, input.c_str(), input.size());
    }

    /*
    * According to the spec[rfc7515],
          x5c contains the X.509 public key certificate or certificate chain corresponding to the
          key used in certificate chain.

    * References:
        rfc 7515: https://tools.ietf.org/html/rfc7515#section-4.1.6
        MSAL c# library: https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/7f6bd863a8b60e0060306672da6cb6d57716eac7/src/client/Microsoft.Identity.Client/Internal/JsonWebToken.cs#L200
    */
    std::string x5c(X509* cert) {
        unsigned char* derBuffer = nullptr;
        auto derBufferLen = i2d_X509(cert, &derBuffer);
        if (derBufferLen >= 0) {
            std::string s;
            for (int i = 0; i < derBufferLen; ++i) {
                s.push_back(derBuffer[i]);
            }
            delete[]derBuffer;
            return toBase64(s);
        }
        else {
            return "";
        }
    }

    std::string x5t(const X509* x509)
    {
        unsigned int mdSize;
        unsigned char md[EVP_MAX_MD_SIZE];
        const EVP_MD* digest = EVP_get_digestbyname("sha1");
        X509_digest(x509, digest, md, &mdSize);
        std::string s;
        for (unsigned int i = 0; i < mdSize; ++i) {
            s.push_back(md[i]);
        }
        std::string base64s = toBase64(s);
        return base64s;
    }

    /*
    header contains algorithm (RS256), type (JWT) and one of
        i) keyid (base64 encoding of thumbprint of the cert) and x5c (base64 encoding of DER format of the cert)
       ii) x5t (the base64 encoding of the thumb print of the cert)
    References:
    rfc7515: https://tools.ietf.org/html/rfc7515#section-4.1
    */
    std::string header(X509* cert, bool useX5c) {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("alg");
        writer.String("RS256");
        writer.Key("typ");
        writer.String("JWT");
        if (useX5c) {
            writer.Key("kid");
            writer.String(x5t(cert).c_str());
            writer.Key("x5c");
            writer.String(x5c(cert).c_str());
        }
        else {
            writer.Key("x5t");
            writer.String(x5t(cert).c_str());
        }
        writer.EndObject();
        return toBase64Url(buffer.GetString());
    }

    std::string payload(const std::string& tenantId, const std::string& clientId) {
        std::string audience{ "https://login.microsoftonline.com/" };
        audience += tenantId;
        audience += "/oauth2/token";
        auto now = std::chrono::system_clock::now();
        auto nbf = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        auto exp = nbf + 7200;
        auto guid = boost::uuids::to_string(boost::uuids::random_generator()());
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("aud");
        writer.String(audience.c_str());
        writer.Key("exp");
        writer.Uint64(exp);
        writer.Key("iss");
        writer.String(clientId.c_str());
        writer.Key("jti");
        writer.String(guid.c_str());
        writer.Key("nbf");
        writer.Uint64(nbf);
        writer.Key("sub");
        writer.String(clientId.c_str());
        writer.EndObject();
        return toBase64Url(buffer.GetString());
    }


    // For cert based auth, we need the JSON-Compact serialization as defined in rfc 7519 (and 7515)
    // Algorithm for JSON-compact
    // 1. Create the content to be used as the JWS Payload.
    // 2. base64Url(payload)
    // 3. create JOSE header
    // 4. base64Url(header)
    // 5. compute the signature in the manner defined for the being used over JWS signing input
    // ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
    // 6. Compute the encoded signature value BASE64URL(JWS Signature).
    // 7. JWS compact serialization = BASE64URL(UTF8(JWS ProtectedHeader)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
    //
    // Active directory expects the algorithm for signing to be RS256 
    //  JOSE header provides three keys - alg, typ and x5t
    //  Claims(payload) contains - aud, exp, iss, jti, nbf and sub
    //   references: http://www.rfc-editor.org/info/rfc7515
    //             https://tools.ietf.org/html/rfc7519
    //             https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
    std::string jwt(const std::string& tenantId, const std::string& clientId, const char* pfxFile, const char* password, bool useX5c) {
        std::string empty;
        auto p12Bio = BIO_new_file(pfxFile, "rb");
        if (p12Bio == nullptr) {
            return empty;
        }
        auto p12 = d2i_PKCS12_bio(p12Bio, nullptr);

        if (p12 == nullptr) {
            return empty;
        }
        EVP_PKEY* pkey;
        X509* cert;
        STACK_OF(X509)* ca = nullptr;
        if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
            auto pkcsErr = ERR_get_error();
            char buffer[256];
            ERR_error_string_n(pkcsErr, buffer, 256);
	    //            LOG(ERROR) << buffer;

            return empty;
        }

        std::stringstream jws;
        jws << header(cert, useX5c);
        jws << '.';
        jws << payload(tenantId, clientId);
        std::string jwsSigningInput = jws.str();
        std::string signedstr;
        signedstr.resize(EVP_PKEY_size(pkey));
        unsigned int len = 0;
        BIO* bmem = BIO_new(BIO_s_mem());
        std::string clientsec;
        char* p = nullptr;
        std::string pkeyMem;
        long keySize = 0;
        auto writePvtKeyStatus = PEM_write_bio_PrivateKey(bmem, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        if (writePvtKeyStatus == 1) {
            keySize = BIO_get_mem_data(bmem, &p);
            for (int i = 0; i < keySize; ++i)
                pkeyMem.push_back(p[i]);

        }
        else {
		//           LOG(ERROR) << "failed to read private key " << std::endl;
        }

        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) {
		//            LOG(ERROR) << " failed to create context " << std::endl;
        }
        if (!EVP_SignInit(ctx.get(), EVP_sha256())) {
		//            LOG(ERROR) << " failed to initialize sign " << std::endl;
        }
        if (!EVP_SignUpdate(ctx.get(), jwsSigningInput.data(), jwsSigningInput.size())) {
		//LOG(ERROR) << " failed to update " << std::endl;
        }
        if (!EVP_SignFinal(ctx.get(), (unsigned char*)signedstr.data(), &len, pkey)) {
		//   LOG(ERROR) << " failed to final " << std::endl;
        }
        signedstr.resize(len);
        jws << '.' << toBase64Url(signedstr);
        return jws.str();
    }
}
