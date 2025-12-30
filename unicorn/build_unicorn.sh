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
[[ -z "$VIRTUAL_ENV" ]] && WRAP="sudo -E python3" || WRAP="python3"

# Set library path for Python bindings to find libunicorn.so
export LD_LIBRARY_PATH="$(pwd)/$BUILD_DIR:$LD_LIBRARY_PATH"
export LIBUNICORN_PATH="$(pwd)/$BUILD_DIR"

pushd "$UC_DIR"/bindings/python && $WRAP setup.py install || { popd; exit 1; }; popd

echo "[+] Unicorn Python bindings installed successfully"
echo "[*] Library location: $(pwd)/$BUILD_DIR/libunicorn.so*"

exit
