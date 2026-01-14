#!/usr/bin/env bash
# Build script for Unicorn 2.x (upstream) with CMake
UC_DIR=fuzzware-unicorn
BUILD_DIR="$UC_DIR/build"

echo "[*] Cleaning previous build..."
rm -rf "$BUILD_DIR"

echo "[*] Configuring Unicorn 2.x with CMake (ARM only)..."
mkdir -p "$BUILD_DIR"
cmake -S "$UC_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DUNICORN_ARCH="arm" \
    -DBUILD_SHARED_LIBS=ON \
    -DUNICORN_BUILD_TESTS=OFF \
    -DUNICORN_INSTALL=OFF \
    || exit 1

echo "[*] Building Unicorn 2.x..."
cmake --build "$BUILD_DIR" -j$(nproc) || exit 1

echo "[+] Unicorn built successfully!"

echo "[*] Installing Unicorn python bindings..."

# install locally when inside a venv and globally otherwise
[[ -z "$VIRTUAL_ENV" ]] && WRAP="sudo -E python3 -m pip" || WRAP="python3 -m pip"

# Set library path for Python bindings to find libunicorn.so
export LD_LIBRARY_PATH="$(pwd)/$BUILD_DIR:$LD_LIBRARY_PATH"
export LIBUNICORN_PATH="$(pwd)/$BUILD_DIR"
if [[ -z "$SETUPTOOLS_SCM_PRETEND_VERSION" ]]; then
    UC_VERSION="$(python3 - <<'PY'
from pathlib import Path
import re

const_path = Path("fuzzware-unicorn/bindings/python/unicorn/unicorn_const.py")
text = const_path.read_text()
major = re.search(r"UC_VERSION_MAJOR\s*=\s*(\d+)", text)
minor = re.search(r"UC_VERSION_MINOR\s*=\s*(\d+)", text)
patch = re.search(r"UC_VERSION_PATCH\s*=\s*(\d+)", text)
if not (major and minor and patch):
    raise SystemExit("Failed to parse unicorn version")
print(f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}")
PY
    )"
    export SETUPTOOLS_SCM_PRETEND_VERSION="$UC_VERSION"
fi

pushd "$UC_DIR"/bindings/python && $WRAP install --no-deps . || { popd; exit 1; }; popd

echo "[+] Unicorn Python bindings installed successfully"
echo "[*] Library location: $(pwd)/$BUILD_DIR/libunicorn.so*"

exit
