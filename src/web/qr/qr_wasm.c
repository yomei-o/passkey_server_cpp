/*
 * QR コード生成を WebAssembly で使うための窓口
 *
 * 中身は Nayuki の QR Code generator（qrcodegen.c、MIT License、無改変）。
 * 標準ライブラリは使わず、qrcodegen.c が呼ぶ数個の関数だけここで用意するので、
 * JavaScript 側の補助コード無しの素の .wasm になる（読み込み方は html/qr.js）。
 *
 * 使い方（JavaScript から）:
 *   1. qr_text_buffer() の位置に UTF-8 の文字列を書き、末尾に 0 を置く（qr_text_capacity() バイトまで）
 *   2. qr_encode(誤り訂正レベル 0〜3) を呼ぶ。戻り値は 1 辺のモジュール数（失敗なら 0）
 *   3. qr_module(x, y) で各マスが黒（1）か白（0）かを読む
 */
#include <stddef.h>
#include <stdint.h>
#include "qrcodegen.h"

/* ---- qrcodegen.c が使う標準関数（-nostdlib なので自前） ---- */

void *memset(void *d, int c, size_t n)
{
    unsigned char *p = (unsigned char *)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}

void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *p = (unsigned char *)d;
    const unsigned char *q = (const unsigned char *)s;
    while (n--) *p++ = *q++;
    return d;
}

void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *p = (unsigned char *)d;
    const unsigned char *q = (const unsigned char *)s;
    if (p < q) {
        while (n--) *p++ = *q++;
    } else {
        p += n;
        q += n;
        while (n--) *--p = *--q;
    }
    return d;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

/* 定数文字列への strchr はコンパイラが memchr に置き換えるので、こちらも要る */
void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    for (; n--; p++) {
        if (*p == (unsigned char)c) return (void *)p;
    }
    return NULL;
}

char *strchr(const char *s, int c)
{
    for (;; s++) {
        if (*s == (char)c) return (char *)s;
        if (!*s) return NULL;
    }
}

int abs(int x) { return x < 0 ? -x : x; }
long labs(long x) { return x < 0 ? -x : x; }

/* ---- JavaScript から呼ぶ関数 ---- */

#define TEXT_CAPACITY 2048

static char text_buf[TEXT_CAPACITY + 1];
static uint8_t qr_buf[qrcodegen_BUFFER_LEN_MAX];
static uint8_t tmp_buf[qrcodegen_BUFFER_LEN_MAX];

__attribute__((export_name("qr_text_buffer")))
char *qr_text_buffer(void) { return text_buf; }

__attribute__((export_name("qr_text_capacity")))
int qr_text_capacity(void) { return TEXT_CAPACITY; }

/* ecc: 0=LOW 1=MEDIUM 2=QUARTILE 3=HIGH。入る範囲でいちばん小さいバージョンを選ぶ */
__attribute__((export_name("qr_encode")))
int qr_encode(int ecc)
{
    if (ecc < qrcodegen_Ecc_LOW || ecc > qrcodegen_Ecc_HIGH) return 0;
    text_buf[TEXT_CAPACITY] = 0;
    if (!qrcodegen_encodeText(text_buf, tmp_buf, qr_buf, (enum qrcodegen_Ecc)ecc,
                              qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true)) {
        return 0;
    }
    return qrcodegen_getSize(qr_buf);
}

__attribute__((export_name("qr_module")))
int qr_module(int x, int y) { return qrcodegen_getModule(qr_buf, x, y) ? 1 : 0; }
