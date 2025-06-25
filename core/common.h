//
// Created by reverccqin on 25-5-15.
//

#ifndef COMMON_H
#define COMMON_H
#include <android/log.h>

#include <cstdint>

#define LOG_TAG "gumtrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

typedef struct module_range {
    uintptr_t base;
    uintptr_t end;
} module_range_t, trace_range_t;


#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
TypeName(const TypeName&) = delete;    \
void operator=(const TypeName&) = delete


#endif //COMMON_H
