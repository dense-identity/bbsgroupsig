#!/usr/bin/env bash
set -euo pipefail

ABI=$1

DN="build-android-$ABI"
rm -rf "$DN"
mkdir "$DN" && cd "$DN"

export ANDROID_NDK_ROOT="$HOME/Library/Android/sdk/ndk/27.0.12077973"

# 1) Initial configure to fetch MCL into _deps/mcl-src
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=$ABI \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_BBSGS_JNI=ON \
  -DBUILD_BBSGS_TESTING=OFF \
  -DBUILD_BBSGS_BENCHMARK=OFF \
  -DMCL_TEST_WITH_GMP=OFF \
  ..

ninja
