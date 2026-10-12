#!/usr/bin/env bash
# Full build + test pipeline for AnDivert (runs on Linux/WSL).
# Usage: bash tools/ci_build_and_test.sh
set -e
cd "$(dirname "$0")/.."

SRC=andivert/src/main/cpp
BUILD=/tmp/andivert-build
mkdir -p "$BUILD"

echo "== 1. compile shared library (warnings are errors) =="
# On a host machine jni.h is usually absent (it ships with the JDK/NDK and
# targets their ABI), so the CI compiles the core engine only; ad_jni.c is
# compiled by the Android build (CMake/NDK) which always has jni.h.
JNI_FLAGS=""
JNI_SRC="$SRC/ad_jni.c"
if [ -n "$JAVA_HOME" ] && [ -f "$JAVA_HOME/include/jni.h" ]; then
    JNI_FLAGS="-I$JAVA_HOME/include -I$JAVA_HOME/include/linux"
elif [ -f /usr/lib/jvm/default-java/include/jni.h ]; then
    JNI_FLAGS="-I/usr/lib/jvm/default-java/include -I/usr/lib/jvm/default-java/include/linux"
else
    JNI_SRC=""
    echo "   (no jni.h on host: building core engine; the JNI bridge is built by the Android/NDK build)"
fi
gcc -O2 -Wall -Wextra -Werror -Wno-unused-parameter -I"$SRC" $JNI_FLAGS -shared -fPIC \
    -o "$BUILD/libandivert.so" \
    "$SRC/andivert.c" "$SRC/ad_packet.c" "$SRC/ad_filter.c" \
    "$SRC/ad_checksum.c" "$SRC/ad_ring.c" "$SRC/ad_forward.c" \
    "$SRC/ad_log.c" $JNI_SRC -lpthread

echo "== 2. build live test harness =="
gcc -O1 -Wall -Wno-unused -I"$SRC" -o "$BUILD/ad_test" \
    andivert/test/ad_test.c \
    "$SRC/andivert.c" "$SRC/ad_packet.c" "$SRC/ad_filter.c" \
    "$SRC/ad_checksum.c" "$SRC/ad_ring.c" "$SRC/ad_forward.c" \
    "$SRC/ad_log.c" -lpthread

echo "== 3. run live tests =="
if ! "$BUILD/ad_test" 2>/dev/null | tail -3; then
    echo "TESTS FAILED"
    exit 1
fi

echo "== 4. syntax-check Kotlin =="
# kotlinc (if present) needs the Android SDK's android.jar for our imports.
AJ="${ANDROID_JAR:-}"
if [ -z "$AJ" ] && [ -n "$ANDROID_HOME" ]; then
    AJ=$(ls "$ANDROID_HOME"/platforms/android-3*/android.jar 2>/dev/null | sort -V | tail -1)
fi
if command -v kotlinc >/dev/null 2>&1 && [ -n "$AJ" ] && [ -f "$AJ" ]; then
    kotlinc -classpath "$AJ" -d /tmp/andivert-classes \
        andivert/src/main/java/com/andivert/library/*.kt
    echo "kotlinc OK"
else
    echo "kotlinc or android.jar not available; Kotlin is validated by the Android build job"
fi

echo "== ALL DONE =="
