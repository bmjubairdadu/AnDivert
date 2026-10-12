/*
 * ad_log.c — thin wrapper over Android logcat; falls back to stderr on host.
 */

#include "ad_internal.h"
#include <stdio.h>
#include <stdarg.h>

#if defined(__ANDROID__)
#include <android/log.h>
#define AD_LOG_TAG "AnDivert"
#endif

void ad_log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#if defined(__ANDROID__)
    __android_log_vprint(ANDROID_LOG_INFO, AD_LOG_TAG, fmt, ap);
#else
    fprintf(stderr, "[andivert:info] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#endif
    va_end(ap);
}

void ad_log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#if defined(__ANDROID__)
    __android_log_vprint(ANDROID_LOG_WARN, AD_LOG_TAG, fmt, ap);
#else
    fprintf(stderr, "[andivert:warn] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#endif
    va_end(ap);
}

void ad_log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#if defined(__ANDROID__)
    __android_log_vprint(ANDROID_LOG_ERROR, AD_LOG_TAG, fmt, ap);
#else
    fprintf(stderr, "[andivert:error] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#endif
    va_end(ap);
}
