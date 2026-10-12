/*
 * ad_jni.c — JNI bridge exposing the AnDivert engine to Kotlin/Java.
 *
 * The Java-facing surface mirrors WinDivert's own API naming, so a developer
 * who knows WinDivert reads this immediately:
 *
 *   long handle = anDivertOpen(fd, "outbound and tcp.DstPort == 443", 0);
 *   byte[] packet = anDivertRecv(handle, timeoutMs);
 *   anDivertSend(handle, packet);
 *   anDivertClose(handle);
 */

#include "ad_internal.h"
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* VpnService.protect(fd) hook                                        */
/* ------------------------------------------------------------------ */

static JavaVM   *g_vm = NULL;
static jobject   g_vpn_protect_target = NULL;   /* global ref to VpnService */
static jmethodID g_protect_mid = NULL;

JNIEXPORT void JNICALL
Java_com_andivert_library_AnDivertNative_nativeSetVpnService(JNIEnv *env, jclass clazz,
                                                             jobject vpn_service)
{
    (void)clazz;
    if (g_vpn_protect_target) {
        (*env)->DeleteGlobalRef(env, g_vpn_protect_target);
        g_vpn_protect_target = NULL;
    }
    if (vpn_service) {
        g_vpn_protect_target = (*env)->NewGlobalRef(env, vpn_service);
    }
    ad_log_info("vpn protect target %s", vpn_service ? "registered" : "cleared");
}

/* Called by the native forwarder before it creates any upstream socket. */
static int ad_jni_protect(int fd)
{
    JNIEnv *env = NULL;
    int attached = 0;
    jboolean ok = JNI_FALSE;

    if (!g_vm || !g_vpn_protect_target || !g_protect_mid)
        return 0;   /* nothing to protect against (host/unit tests) */

    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK)
            return -1;
        attached = 1;
    }
    ok = (*env)->CallBooleanMethod(env, g_vpn_protect_target, g_protect_mid, (jint)fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        ok = JNI_FALSE;
    }
    if (attached)
        (*g_vm)->DetachCurrentThread(g_vm);
    return ok == JNI_TRUE ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Library load                                                       */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass cls;
    (void)reserved;

    g_vm = vm;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    /* cache VpnService.protect(int) */
    cls = (*env)->FindClass(env, "android/net/VpnService");
    if (cls) {
        g_protect_mid = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
        (*env)->DeleteLocalRef(env, cls);
    }
    AnDivertSetProtectFn(ad_jni_protect);
    ad_log_info("AnDivert native loaded (v%d.%d)",
                AN_DIVERT_VERSION_MAJOR, AN_DIVERT_VERSION_MINOR);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    (void)reserved;
    AnDivertSetProtectFn(NULL);
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK &&
        g_vpn_protect_target) {
        (*env)->DeleteGlobalRef(env, g_vpn_protect_target);
        g_vpn_protect_target = NULL;
    }
    g_vm = NULL;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

JNIEXPORT jlong JNICALL
Java_com_andivert_library_AnDivertNative_nativeOpen(JNIEnv *env, jclass clazz,
                                                    jint tun_fd, jstring filter,
                                                    jint layer, jint priority,
                                                    jlong flags)
{
    const char *cfilter = NULL;
    jlong handle;
    (void)clazz;

    if (filter)
        cfilter = (*env)->GetStringUTFChars(env, filter, NULL);

    handle = (jlong)(intptr_t)AnDivertOpen((int)tun_fd, cfilter,
                                           (int)layer, (int)priority,
                                           (uint64_t)flags);
    if (cfilter)
        (*env)->ReleaseStringUTFChars(env, filter, cfilter);

    if (!handle)
        ad_log_error("nativeOpen failed: %s", AnDivertStrError(AnDivertLastError()));
    return handle;
}

JNIEXPORT void JNICALL
Java_com_andivert_library_AnDivertNative_nativeClose(JNIEnv *env, jclass clazz,
                                                     jlong handle)
{
    (void)env; (void)clazz;
    if (handle)
        AnDivertClose((ad_handle_t *)(intptr_t)handle);
}

/* ------------------------------------------------------------------ */
/* Recv / Send                                                        */
/* ------------------------------------------------------------------ */

/*
 * Returns the packet as a byte[], or null on timeout/error.
 * `meta` is an int[6] out-parameter:
 *   [0] flags, [1] protocol, [2] src port, [3] dst port,
 *   [4] src addr as int (v4), [5] dst addr as int (v4)
 */
JNIEXPORT jbyteArray JNICALL
Java_com_andivert_library_AnDivertNative_nativeRecv(JNIEnv *env, jclass clazz,
                                                    jlong handle, jint timeout_ms,
                                                    jintArray meta)
{
    uint8_t *buf;
    AD_ADDRESS addr;
    uint32_t recv_len = 0;
    int rc;
    jbyteArray out = NULL;

    (void)clazz;
    if (!handle)
        return NULL;

    buf = (uint8_t *)malloc(AD_MAX_PACKET);
    if (!buf)
        return NULL;

    memset(&addr, 0, sizeof(addr));
    rc = AnDivertRecv((ad_handle_t *)(intptr_t)handle, buf, AD_MAX_PACKET,
                      &addr, &recv_len, (uint32_t)timeout_ms);
    if (rc == AN_SUCCESS && recv_len > 0) {
        out = (*env)->NewByteArray(env, (jsize)recv_len);
        if (out)
            (*env)->SetByteArrayRegion(env, out, 0, (jsize)recv_len, (jbyte *)buf);

        if (meta) {
            jint m[6];
            uint8_t version = buf[0] >> 4;
            uint8_t proto = 0;
            jint sport = -1, dport = -1, src = 0, dst = 0;

            memset(m, 0, sizeof(m));
            m[0] = (jint)addr.flags;

            if (version == 4 && recv_len >= 20) {
                int off = ad_transport_offset(buf, recv_len);
                proto = buf[9];
                memcpy(&src, buf + 12, 4);
                memcpy(&dst, buf + 16, 4);
                if (off > 0 && (proto == 6 || proto == 17) &&
                    recv_len >= (uint32_t)off + 4) {
                    sport = ((jint)buf[off] << 8) | buf[off + 1];
                    dport = ((jint)buf[off + 2] << 8) | buf[off + 3];
                }
            } else if (version == 6 && recv_len >= 40) {
                proto = buf[6];
            }
            m[1] = proto;
            m[2] = sport;
            m[3] = dport;
            m[4] = src;
            m[5] = dst;
            (*env)->SetIntArrayRegion(env, meta, 0, 6, m);
        }
    }
    free(buf);
    return out;
}

JNIEXPORT jint JNICALL
Java_com_andivert_library_AnDivertNative_nativeSend(JNIEnv *env, jclass clazz,
                                                    jlong handle, jbyteArray packet)
{
    jsize len;
    jbyte *bytes;
    uint32_t sent = 0;
    int rc;
    (void)clazz;

    if (!handle || !packet)
        return AN_ERROR_INVALID;
    len = (*env)->GetArrayLength(env, packet);
    if (len <= 0)
        return AN_ERROR_INVALID;

    bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    if (!bytes)
        return AN_ERROR_NOMEM;

    rc = AnDivertSend((ad_handle_t *)(intptr_t)handle, bytes, (uint32_t)len,
                      NULL, &sent);
    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Stats / errors / helpers                                           */
/* ------------------------------------------------------------------ */

JNIEXPORT jlongArray JNICALL
Java_com_andivert_library_AnDivertNative_nativeGetStats(JNIEnv *env, jclass clazz,
                                                        jlong handle)
{
    AD_STATS s;
    jlong v[8];
    jlongArray out;
    (void)clazz;

    if (!handle)
        return NULL;
    if (AnDivertGetStats((ad_handle_t *)(intptr_t)handle, &s) != AN_SUCCESS)
        return NULL;

    v[0] = (jlong)s.packets_divered;
    v[1] = (jlong)s.packets_passed;
    v[2] = (jlong)s.packets_dropped;
    v[3] = (jlong)s.bytes_in;
    v[4] = (jlong)s.bytes_out;
    v[5] = (jlong)s.queue_len;
    v[6] = (jlong)s.queue_max;

    out = (*env)->NewLongArray(env, 7);
    if (out)
        (*env)->SetLongArrayRegion(env, out, 0, 7, v);
    return out;
}

JNIEXPORT jint JNICALL
Java_com_andivert_library_AnDivertNative_nativeLastError(JNIEnv *env, jclass clazz)
{
    (void)env; (void)clazz;
    return AnDivertLastError();
}

JNIEXPORT jstring JNICALL
Java_com_andivert_library_AnDivertNative_nativeStrError(JNIEnv *env, jclass clazz,
                                                        jint err)
{
    (void)clazz;
    return (*env)->NewStringUTF(env, AnDivertStrError((int)err));
}

/* Validate a filter without opening a handle — handy for UI input. */
JNIEXPORT jboolean JNICALL
Java_com_andivert_library_AnDivertNative_nativeValidateFilter(JNIEnv *env, jclass clazz,
                                                              jstring filter)
{
    const char *cfilter;
    ad_filter_t *f;
    (void)clazz;

    cfilter = filter ? (*env)->GetStringUTFChars(env, filter, NULL) : NULL;
    f = ADFilterCompile(cfilter);
    if (cfilter)
        (*env)->ReleaseStringUTFChars(env, filter, cfilter);
    if (f) {
        ADFilterFree(f);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_andivert_library_AnDivertNative_nativeFilterError(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    return (*env)->NewStringUTF(env, ADFilterError());
}

JNIEXPORT jstring JNICALL
Java_com_andivert_library_AnDivertNative_nativeVersion(JNIEnv *env, jclass clazz)
{
    char buf[32];
    (void)clazz;
    snprintf(buf, sizeof(buf), "%d.%d", AN_DIVERT_VERSION_MAJOR,
             AN_DIVERT_VERSION_MINOR);
    return (*env)->NewStringUTF(env, buf);
}
