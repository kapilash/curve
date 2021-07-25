#define CURVE_DLL
#define CURVE_LIBRARY_EXPORT
#include "Curve.h"

#include <string>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#if defined(WIN32) || defined(_WIN32)
#ifndef GLOG_NO_ABBREVIATED_SEVERITIES
#define GLOG_NO_ABBREVIATED_SEVERITIES
#endif
#endif
#include <glog/logging.h>

void curve_init_logging()
{
    google::InitGoogleLogging("curve");
}

void curve_destroy_str(void* str)
{
    auto ptr = static_cast<std::string*>(str);
    delete ptr;
}

const char* curve_get_string(void* str)
{
    auto ptr = static_cast<std::string*>(str);
    return ptr->c_str();
}

size_t curve_get_strlen(void* str)
{
    auto ptr = static_cast<std::string*>(str);
    return ptr->size();
}
