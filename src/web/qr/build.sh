#!/bin/bash
#
# qr_wasm.c + qrcodegen.c を素の WebAssembly（qr.wasm）にして、cpp/html と python/html に置く。
#
#   bash src/web/qr/build.sh
#
# WebAssembly を出せる clang が要る。環境変数 CLANG で指定できる。無ければ PATH の clang、
# だめなら Emscripten SDK に入っている clang（$EMSDK/upstream/bin/clang）を探す。
# Emscripten の補助 JS は使わない（-nostdlib）。ヘッダだけ Emscripten の sysroot から借りる。
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

can_wasm() {
    echo 'int f(void){return 0;}' | "$1" --target=wasm32 -x c -c -o /dev/null - 2>/dev/null
}

if [ -z "$CLANG" ]; then
    for c in clang "${EMSDK:-/c/prog/emsdk/emsdk}/upstream/bin/clang" "$HOME/emsdk/upstream/bin/clang"; do
        if command -v "$c" >/dev/null 2>&1 && can_wasm "$c"; then CLANG="$c"; break; fi
    done
fi
[ -n "$CLANG" ] || { echo "wasm32 を出せる clang が見つからない（CLANG=... で指定）" >&2; exit 1; }
echo "### clang: $CLANG"

# stdint.h などのヘッダ。Emscripten の sysroot があれば使い、無ければ clang 内蔵の freestanding ヘッダ
SYSROOT=""
for d in "$(dirname "$CLANG")/../emscripten/cache/sysroot" "${EMSDK:-/c/prog/emsdk/emsdk}/upstream/emscripten/cache/sysroot"; do
    if [ -f "$d/include/string.h" ]; then SYSROOT="--sysroot=$d"; break; fi
done

"$CLANG" --target=wasm32 -O2 -nostdlib $SYSROOT -DNDEBUG \
    -Wl,--no-entry -Wl,--strip-all \
    -o "$HERE/qr.wasm" "$HERE/qr_wasm.c" "$HERE/qrcodegen.c"

for d in cpp python; do
    cp "$HERE/qr.wasm" "$REPO/src/server_sample/$d/html/qr.wasm"
done
echo "### qr.wasm: $(wc -c < "$HERE/qr.wasm") bytes -> src/server_sample/{cpp,python}/html/"
