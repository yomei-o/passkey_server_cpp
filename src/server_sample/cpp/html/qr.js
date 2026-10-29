// QR コードを qr.wasm（Nayuki の QR Code generator を WebAssembly にしたもの、src/web/qr/）で作って SVG で返す。
//
//   const el = await QR.svg("https://...", { size: 200 });   // SVG 要素
//
// qr.wasm は Emscripten の補助コード無しの素の WebAssembly なので、fetch して instantiate するだけ。
// MIME 型（application/wasm）に頼らないよう instantiateStreaming は使わない。
"use strict";

const QR = (() => {
  // qr.wasm は qr.js と同じ場所に置く（currentScript は読み込み中しか取れないので先に覚える）
  const WASM_URL = new URL("qr.wasm", document.currentScript ? document.currentScript.src : location.href);
  let exportsPromise = null;

  function load() {
    if (!exportsPromise) {
      exportsPromise = fetch(WASM_URL)
        .then((r) => {
          if (!r.ok) throw new Error("qr.wasm を読み込めません (" + r.status + ")");
          return r.arrayBuffer();
        })
        .then((b) => WebAssembly.instantiate(b))
        .then((r) => r.instance.exports);
    }
    return exportsPromise;
  }

  // ecc: 0=LOW 1=MEDIUM 2=QUARTILE 3=HIGH。戻り値は行ごとの真偽値の配列
  async function matrix(text, ecc) {
    const e = await load();
    const bytes = new TextEncoder().encode(text);
    const cap = e.qr_text_capacity();
    if (bytes.length > cap) throw new Error("QR コードにするには長すぎます");
    const mem = new Uint8Array(e.memory.buffer, e.qr_text_buffer(), cap + 1);
    mem.set(bytes);
    mem[bytes.length] = 0;
    const n = e.qr_encode(ecc == null ? 1 : ecc);
    if (!n) throw new Error("QR コードを作れません");
    const rows = [];
    for (let y = 0; y < n; y++) {
      const row = new Array(n);
      for (let x = 0; x < n; x++) row[x] = e.qr_module(x, y) === 1;
      rows.push(row);
    }
    return rows;
  }

  // 黒いマスを横に続く分ずつまとめて 1 本の path にする。周りに 4 マスの余白（クワイエットゾーン）
  async function svg(text, opts) {
    opts = opts || {};
    const rows = await matrix(text, opts.ecc);
    const n = rows.length;
    const margin = 4;
    let d = "";
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        if (!rows[y][x]) continue;
        let w = 1;
        while (x + w < n && rows[y][x + w]) w++;
        d += "M" + (x + margin) + "," + (y + margin) + "h" + w + "v1h-" + w + "z";
        x += w - 1;
      }
    }
    const ns = "http://www.w3.org/2000/svg";
    const s = document.createElementNS(ns, "svg");
    const total = n + margin * 2;
    s.setAttribute("viewBox", "0 0 " + total + " " + total);
    s.setAttribute("width", opts.size || 200);
    s.setAttribute("height", opts.size || 200);
    s.setAttribute("shape-rendering", "crispEdges");
    s.setAttribute("role", "img");
    s.setAttribute("aria-label", "QR コード: " + text);
    // 読み取れるよう、ダークモードでも白地に黒で描く
    const bg = document.createElementNS(ns, "rect");
    bg.setAttribute("width", total);
    bg.setAttribute("height", total);
    bg.setAttribute("fill", "#ffffff");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    p.setAttribute("fill", "#000000");
    s.append(bg, p);
    return s;
  }

  return { load, matrix, svg };
})();
