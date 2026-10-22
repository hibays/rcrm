# Android arm64-v8a toolchain shim for zxing-cpp's bundled CMake build.
#
# The zxing-cpp crate builds its C++ core through cmake-rs. cmake-rs accepts a
# per-target toolchain file (CMAKE_TOOLCHAIN_FILE_<target>), and the NDK's own
# toolchain requires ANDROID_ABI to be set before it is included — hence one
# shim per ABI, selected by the build scripts. ANDROID_STL=c++_static keeps the
# C++ runtime inside the .so (no libc++_shared.so to package); the Rust link
# adds the same runtime through target-scoped -lc++_static flags.
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-24)
set(ANDROID_STL c++_static)
file(TO_CMAKE_PATH "$ENV{ANDROID_NDK_HOME}" _rcrm_ndk)
include("${_rcrm_ndk}/build/cmake/android.toolchain.cmake")
