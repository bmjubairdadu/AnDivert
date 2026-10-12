"""Builds the AnDivert release artifacts: AAR + raw release zip."""
import zipfile, os, shutil

WS = r"D:\AnDivert"
STAGE = os.path.join(WS, ".aar-stage")
DIST = os.path.join(WS, "dist")

MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.andivert.library"/>\n'
)

# ---------------------------------------------------------------- AAR ----
aar_path = os.path.join(DIST, "andivert-1.0.0.aar")
classes_jar = os.path.join(DIST, "andivert-classes.jar")

# Prefer the authoritative Gradle-built AAR when available; fall back to
# hand-assembly from the staging dir (e.g. on a machine without the SDK).
_gradle_aar = os.path.join(WS, "andivert", "build", "outputs", "aar",
                           "andivert-release.aar")
if os.path.exists(_gradle_aar):
    shutil.copyfile(_gradle_aar, aar_path)
    print("AAR: using Gradle build output")
    _gradle_aar_used = True
else:
    _gradle_aar_used = False

with zipfile.ZipFile(classes_jar, "w", zipfile.ZIP_DEFLATED) as c:
    if _gradle_aar_used:
        import io
        with zipfile.ZipFile(aar_path) as a:
            c.writestr("classes.jar", a.read("classes.jar"))
    else:
        classes_dir = os.path.join(DIST, "classes")
        for root, _, fs in os.walk(classes_dir):
            for f in sorted(fs):
                if f.endswith(".class"):
                    p = os.path.join(root, f)
                    arc = os.path.relpath(p, classes_dir).replace(os.sep, "/")
                    c.write(p, arc)

if not _gradle_aar_used:
    with zipfile.ZipFile(aar_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", MANIFEST)
        z.writestr("public.txt", "")
        z.writestr("R.txt", "")
        z.write(classes_jar, "classes.jar")
        for abi in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]:
            so = os.path.join(STAGE, "jni", abi, "libandivert.so")
            z.write(so, "jni/{}/libandivert.so".format(abi))
        z.write(os.path.join(STAGE, "jni", "andivert.h"), "andivert.h")
# when the Gradle AAR is used it is copied verbatim above

print("AAR:", os.path.getsize(aar_path), "bytes")

# ------------------------------------------------------- release zip ----
rel_path = os.path.join(DIST, "andivert-1.0.0-release.zip")
src_cpp = os.path.join(WS, "andivert", "src", "main", "cpp")

with zipfile.ZipFile(rel_path, "w", zipfile.ZIP_DEFLATED) as z:
    # prebuilt shared libraries per ABI (the WinDivert.dll equivalent)
    for abi in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]:
        so = os.path.join(DIST, abi, "libandivert.so")
        z.write(so, "andivert-1.0.0/prebuilt/{}/libandivert.so".format(abi))
    # public C header (the WinDivert.h equivalent)
    z.write(os.path.join(src_cpp, "andivert.h"),
            "andivert-1.0.0/include/andivert.h")
    # full native source, so developers can vendor/rebuild
    for f in ["andivert.c", "ad_packet.c", "ad_filter.c", "ad_checksum.c",
              "ad_ring.c", "ad_forward.c", "ad_log.c", "ad_jni.c",
              "ad_internal.h", "CMakeLists.txt"]:
        z.write(os.path.join(src_cpp, f),
                "andivert-1.0.0/src/{}".format(f))
    # Kotlin integration layer sources
    kdir = os.path.join(WS, "andivert", "src", "main", "java",
                        "com", "andivert", "library")
    for f in ["AnDivert.kt", "AnDivertNative.kt", "AnDivertVpnService.kt"]:
        z.write(os.path.join(kdir, f),
                "andivert-1.0.0/kotlin/com/andivert/library/{}".format(f))
    # compiled Kotlin classes + aar for direct consumption
    z.write(classes_jar, "andivert-1.0.0/kotlin-classes.jar")
    z.write(aar_path, "andivert-1.0.0/andivert-1.0.0.aar")
    # example app
    z.write(os.path.join(WS, "examples", "sample-app", "GateActivity.kt"),
            "andivert-1.0.0/examples/GateActivity.kt")
    z.write(os.path.join(WS, "examples", "sample-app", "AndroidManifest.xml"),
            "andivert-1.0.0/examples/AndroidManifest.xml")

print("release zip:", os.path.getsize(rel_path), "bytes")
