#!/usr/bin/env bash
# Build icc's C dependency closure as STATIC libraries into a private prefix, so
# the shipped macOS `icc` links them statically and runs on a stock Mac with NO
# Homebrew installed.
#
# A *fully* static macOS binary is impossible — Apple ships no static libSystem —
# so the target is "third-party static, system dynamic": libfido2 (+ openssl, libcbor)
# become .a archives here, while the always-present macOS system pieces (libSystem,
# CoreFoundation, IOKit, Security, PCSC, libz) stay dynamic. chalresp's go-hid uses the
# native IOHIDManager backend on macOS (IOKit/CoreFoundation frameworks — no lib to
# build) and the pcsc backend's scard links only the system PCSC framework. Every
# lib installs with --disable-shared / BUILD_SHARED_LIBS=OFF so ONLY .a archives
# land in $PREFIX (no .dylib for the runtime to resolve); the release build then
# points cgo's pkg-config at $PREFIX, and because nothing but .a is present the
# link is static (no -static flag — that fails on macOS).
#
# Idempotent + cache-friendly: a marker file short-circuits a warm cache. The CI
# cache key hashes this file, so bumping a version below forces a clean rebuild.
#
# Usage: PREFIX=/path/to/deps scripts/build-macos-static-deps.sh
set -euo pipefail

PREFIX="${PREFIX:?set PREFIX to the install dir}"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# Pinned dependency versions. If a first CI run 404s or a tag drifts, adjust here.
# Sources: openssl/libcbor via GitHub releases; libfido2 via developers.yubico.com.
OPENSSL_VER="${OPENSSL_VER:-3.4.0}"
LIBCBOR_VER="${LIBCBOR_VER:-0.11.0}"
LIBFIDO2_VER="${LIBFIDO2_VER:-1.15.0}"

MARKER="$PREFIX/.icc-static-deps-ok"
if [ -f "$MARKER" ]; then
  echo "== static deps already present at $PREFIX (cache hit) — skipping =="
  exit 0
fi

mkdir -p "$PREFIX" "$PREFIX/src"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export CMAKE_PREFIX_PATH="$PREFIX"
# macOS defaults to PIC, but be explicit so x86_64 archives link into Go's PIE.
export CFLAGS="${CFLAGS:-} -fPIC -O2"

cd "$PREFIX/src"
fetch() { echo "==> fetch $1"; curl -fsSL "$1" -o "$2"; }

cmake_static() { # <srcdir> [extra cmake args...]
  local src="$1"; shift
  # Build OUT of source ("${src}-build", not "$src/build"): recent libcbor ships a
  # Bazel `BUILD` file that case-collides with `build` on case-insensitive APFS.
  # CMAKE_POLICY_VERSION_MINIMUM=3.5: CMake 4.x removed support for projects that
  # declare cmake_minimum_required(VERSION <3.5) (libcbor does). This floor
  # lets them configure; harmless for projects already requiring >=3.5.
  cmake -S "$src" -B "${src}-build" -G "Unix Makefiles" \
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_PREFIX_PATH="$PREFIX" "$@"
  # Build THEN install (two steps): a combined `--target install` doesn't compile
  # first, so it installs headers but never builds the .a.
  cmake --build "${src}-build" -j "$JOBS"
  cmake --install "${src}-build"
}

autotools_static() { # <srcdir> [extra configure args...]
  local src="$1"; shift
  ( cd "$src" && ./configure --enable-static --disable-shared --with-pic \
      --disable-dependency-tracking --prefix="$PREFIX" "$@" \
    && make -j "$JOBS" && make install )
}

# 1. OpenSSL (libcrypto/libssl) — no-shared ⇒ only .a; install_sw skips docs.
fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" openssl.tgz
tar xf openssl.tgz
( cd "openssl-${OPENSSL_VER}" \
  && ./Configure no-shared no-tests no-docs --prefix="$PREFIX" --libdir=lib \
  && make -j "$JOBS" && make install_sw )

# 2. libcbor (cmake, no deps)
fetch "https://github.com/PJK/libcbor/archive/refs/tags/v${LIBCBOR_VER}.tar.gz" libcbor.tgz
tar xf libcbor.tgz
cmake_static "libcbor-${LIBCBOR_VER}" -DWITH_EXAMPLES=OFF

# 3. libfido2 (cmake) — needs libcbor + openssl (both in $PREFIX) + zlib (SDK).
# On macOS libfido2 uses the native IOKit HID backend (no libusb). BUILD_TOOLS=OFF
# skips the CLI tools we don't ship.
fetch "https://developers.yubico.com/libfido2/Releases/libfido2-${LIBFIDO2_VER}.tar.gz" libfido2.tgz
tar xf libfido2.tgz
cmake_static "libfido2-${LIBFIDO2_VER}" \
  -DBUILD_EXAMPLES=OFF -DBUILD_MANPAGES=OFF -DBUILD_TOOLS=OFF

touch "$MARKER"
echo "== static dep prefix ready: $PREFIX =="
ls -1 "$PREFIX/lib"/*.a
