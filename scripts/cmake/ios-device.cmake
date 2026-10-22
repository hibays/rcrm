# iOS iphoneos toolchain shim for zxing-cpp's bundled CMake build.
#
# cmake-rs only sets CMAKE_SYSTEM_NAME/CMAKE_OSX_ARCHITECTURES when it derives
# them itself; a toolchain file is its own declaration (that is how the Android
# shims work), so the iOS shim states everything the C++ build needs. This is
# the same platform setup a plain CMake iOS build uses.
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_ARCHITECTURES arm64)
set(CMAKE_OSX_SYSROOT iphoneos)
set(CMAKE_OSX_DEPLOYMENT_TARGET 13.0)
