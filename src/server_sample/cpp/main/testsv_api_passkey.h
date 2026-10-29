#ifndef API_PASSKEY_H_
#define API_PASSKEY_H_

//
// passkey（WebAuthn）API
//
//   /api/passkey/v0/register_options   登録の準備。トークン無しなら新規アカウント、有りなら自分に追加
//   /api/passkey/v0/register_verify    認証器の応答を検証して公開鍵を保存
//   /api/passkey/v0/login_options      ログインの準備
//   /api/passkey/v0/login_verify       署名を検証してセッションを発行
//   /api/passkey/v0/me                 トークンの確認
//   /api/passkey/v0/logout             セッションを消す
//   /api/passkey/v0/list               自分のパスキー一覧（サーバが何を保存しているか）
//   /api/passkey/v0/delete             自分のパスキーを削除（最後の 1 本ならアカウントごと消える）
//
//   /api/account/v0/list               全アカウントの一覧（全体の管理者だけ）
//   /api/account/v0/delete             自分以外のアカウントを消す（全体の管理者だけ）
//   /api/account/v0/demote             全体の管理者を一般に戻す（全体の管理者だけ。自分も可）
//
//   /api/account/v0/admin_request          全体の管理者に申請する（ログインしていれば誰でも）
//   /api/account/v0/admin_request_cancel   自分の申請を取り下げる
//   /api/account/v0/admin_requests         申請の一覧（全体の管理者だけ）
//   /api/account/v0/admin_approve          申請を承認して全体の管理者にする（全体の管理者だけ）
//   /api/account/v0/admin_reject           申請を却下する（全体の管理者だけ）
//
// 誰でも登録できる。最初の 1 人は全体の管理者（テナントの追加・削除ができる）、2 人目からは一般。
// 2 人目からの全体の管理者は、本人が申請して、全体の管理者が承認する（一覧から選んで上げることはしない）。
// 電気を操作できるかどうかはテナントのメンバーかどうかで決まる（testsv_api_tenant.h）。
//
// Python 版は python/testsv_api_passkey.py。検査の順番と失敗時の message を揃えてある。
// 署名検証は同梱の mbedtls（mbedtlspp.hpp）。
//

#include <cstdint>
#include <ctime>
#include <mutex>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>

#include "lambda_server.h"
#include "database.h"
#include "model_passkey.h"
#include "model_tenant.h"
#include "picosha2.h"
#include "mbedtlspp.hpp"

namespace passkey {

    // セッションの有効期間（時間）
    static const int SESSION_EXPIRE_HOURS = 24;
    // チャレンジの有効期間（秒）
    static const int PASSKEY_CHALLENGE_EXPIRE_SECONDS = 300;
    // ブラウザに渡す timeout（ミリ秒）
    static const int PASSKEY_TIMEOUT_MS = 60000;
    // ユーザ名の長さの上限（UTF-8 のバイト数）
    static const size_t USER_NAME_MAX_BYTES = 64;

    static const int COSE_ALG_ES256 = -7;
    static const int COSE_ALG_RS256 = -257;

    // authenticatorData の flags
    static const int FLAG_UP = 0x01;
    static const int FLAG_UV = 0x04;
    static const int FLAG_BE = 0x08;
    static const int FLAG_BS = 0x10;
    static const int FLAG_AT = 0x40;

    static const char* const ACCOUNT_APPROVED = "approved";
    static const char* const ACCOUNT_PENDING = "pending";
    static const char* const ROLE_ADMIN = "admin";
    static const char* const ROLE_MEMBER = "member";

    static const char* const PASSKEY_COLUMNS[] = {
        "user", "name", "credential_id", "user_handle", "alg", "public_key", "sign_count",
        "transports", "backup_eligible", "backed_up", "aaguid", "last_used_at", "created_at",
    };

    typedef std::vector<uint8_t> bytes;

    struct PasskeyError : std::runtime_error {
        explicit PasskeyError(const std::string& m) : std::runtime_error(m) {}
    };

    //
    // 時刻（naive な UTC の "YYYY-MM-DD HH:MM:SS"。Python 版と同じ DB を読めるように）
    //

    static inline std::string time_to_db(time_t t)
    {
        std::tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &t);
#else
        gmtime_r(&t, &tm_buf);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    static inline time_t db_to_time(const std::string& s)
    {
        std::tm tm_buf = {};
        std::istringstream iss(s);
        iss >> std::get_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        if (iss.fail()) {
            return 0;
        }
#ifdef _WIN32
        return _mkgmtime(&tm_buf);
#else
        return timegm(&tm_buf);
#endif
    }

    // DB から読んだ時刻を表示用にそろえる（Python 版が書くと小数秒が付くので切る）
    static inline json format_time(const std::string& s)
    {
        if (s.empty()) return nullptr;
        return s.substr(0, 19);
    }

    static inline bytes random_bytes(size_t n)
    {
        static std::random_device rd;
        bytes b(n);
        for (size_t i = 0; i < n; i++) {
            b[i] = (uint8_t)(rd() & 0xff);
        }
        return b;
    }

    static inline std::string to_hex(const bytes& b)
    {
        static const char hex[] = "0123456789abcdef";
        std::string s;
        for (uint8_t c : b) {
            s += hex[c >> 4];
            s += hex[c & 15];
        }
        return s;
    }

    static inline bytes sha256(const bytes& in)
    {
        bytes out(32);
        picosha2::hash256(in.begin(), in.end(), out.begin(), out.end());
        return out;
    }

    static inline bytes to_bytes(const std::string& s)
    {
        return bytes(s.begin(), s.end());
    }

    //
    // base64url
    //

    static inline std::string b64url_encode(const bytes& b)
    {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string s;
        size_t i = 0;
        for (; i + 2 < b.size(); i += 3) {
            uint32_t v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
            s += tbl[(v >> 18) & 63]; s += tbl[(v >> 12) & 63];
            s += tbl[(v >> 6) & 63]; s += tbl[v & 63];
        }
        if (b.size() - i == 1) {
            uint32_t v = b[i] << 16;
            s += tbl[(v >> 18) & 63]; s += tbl[(v >> 12) & 63];
        }
        else if (b.size() - i == 2) {
            uint32_t v = (b[i] << 16) | (b[i + 1] << 8);
            s += tbl[(v >> 18) & 63]; s += tbl[(v >> 12) & 63]; s += tbl[(v >> 6) & 63];
        }
        return s;
    }

    // '+' '/' と末尾の '=' も受け付ける。それ以外の文字は invalid request
    static inline bytes b64url_decode(const json& j)
    {
        if (!j.is_string()) throw PasskeyError("invalid request");
        std::string s = j;
        while (!s.empty() && s.back() == '=') s.pop_back();
        if (s.size() % 4 == 1) throw PasskeyError("invalid request");
        bytes out;
        uint32_t v = 0;
        int n = 0;
        for (char c : s) {
            int d;
            if (c >= 'A' && c <= 'Z') d = c - 'A';
            else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
            else if (c >= '0' && c <= '9') d = c - '0' + 52;
            else if (c == '-' || c == '+') d = 62;
            else if (c == '_' || c == '/') d = 63;
            else throw PasskeyError("invalid request");
            v = (v << 6) | d;
            n += 6;
            if (n >= 8) {
                n -= 8;
                out.push_back((uint8_t)((v >> n) & 0xff));
            }
        }
        return out;
    }

    //
    // CBOR（WebAuthn で出てくる範囲だけ：整数・バイト列・文字列・配列・マップ・true/false/null）
    //

    struct Cbor {
        enum Type { UINT, NINT, BYTES, TEXT, ARRAY, MAP, BOOL, NUL } type = NUL;
        int64_t i = 0;              // UINT / NINT の値
        std::string s;              // BYTES / TEXT の中身
        bool b = false;
        std::vector<Cbor> arr;
        std::vector<std::pair<Cbor, Cbor>> map;

        bool is_int() const { return type == UINT || type == NINT; }

        // 整数キー / 文字列キーで引く。無ければ nullptr
        const Cbor* get(int64_t key) const {
            for (auto& kv : map) {
                if (kv.first.is_int() && kv.first.i == key) return &kv.second;
            }
            return nullptr;
        }
        const Cbor* get(const std::string& key) const {
            for (auto& kv : map) {
                if (kv.first.type == TEXT && kv.first.s == key) return &kv.second;
            }
            return nullptr;
        }
    };

    // 戻り値は次の位置。COSE_Key の後ろに拡張データが続くので位置が要る
    static inline size_t cbor_decode(const bytes& d, size_t pos, Cbor& out, int depth = 0)
    {
        if (pos >= d.size() || depth > 16) throw PasskeyError("invalid request");
        uint8_t ib = d[pos++];
        int major = ib >> 5;
        int info = ib & 0x1f;
        uint64_t val;
        if (info < 24) {
            val = info;
        }
        else if (info >= 24 && info <= 27) {
            size_t n = (size_t)1 << (info - 24);
            if (pos + n > d.size()) throw PasskeyError("invalid request");
            val = 0;
            for (size_t k = 0; k < n; k++) val = (val << 8) | d[pos++];
        }
        else {
            throw PasskeyError("invalid request");
        }

        switch (major) {
        case 0:
        case 1:
            if (val > (uint64_t)INT64_MAX) throw PasskeyError("invalid request");
            out.type = major == 0 ? Cbor::UINT : Cbor::NINT;
            out.i = major == 0 ? (int64_t)val : -1 - (int64_t)val;
            return pos;
        case 2:
        case 3:
            if (val > d.size() - pos) throw PasskeyError("invalid request");
            out.type = major == 2 ? Cbor::BYTES : Cbor::TEXT;
            out.s.assign(d.begin() + pos, d.begin() + pos + (size_t)val);
            if (major == 3) {
                // UTF-8 として正しいか（Python 版の decode("utf-8") に合わせる）。
                // nlohmann::json の dump は不正な UTF-8 で例外を投げる
                try { json j = out.s; (void)j.dump(); }
                catch (...) { throw PasskeyError("invalid request"); }
            }
            return pos + (size_t)val;
        case 4:
            if (val > d.size()) throw PasskeyError("invalid request");
            out.type = Cbor::ARRAY;
            for (uint64_t k = 0; k < val; k++) {
                Cbor c;
                pos = cbor_decode(d, pos, c, depth + 1);
                out.arr.push_back(c);
            }
            return pos;
        case 5:
            if (val > d.size()) throw PasskeyError("invalid request");
            out.type = Cbor::MAP;
            for (uint64_t k = 0; k < val; k++) {
                Cbor key, v;
                pos = cbor_decode(d, pos, key, depth + 1);
                pos = cbor_decode(d, pos, v, depth + 1);
                if (key.type == Cbor::ARRAY || key.type == Cbor::MAP) throw PasskeyError("invalid request");
                out.map.push_back(std::make_pair(key, v));
            }
            return pos;
        case 7:
            if (info == 20 || info == 21) {
                out.type = Cbor::BOOL;
                out.b = info == 21;
                return pos;
            }
            if (info == 22) {
                out.type = Cbor::NUL;
                return pos;
            }
            break;
        }
        throw PasskeyError("invalid request");
    }

    //
    // rpId / origin
    //

    static inline std::string env_(const char* name)
    {
        const char* p = getenv(name);
        return p ? p : "";
    }

    static inline std::string trim_(const std::string& s)
    {
        size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos) return "";
        size_t b = s.find_last_not_of(" \t");
        return s.substr(a, b - a + 1);
    }

    static inline std::string first_of_list(const std::string& s)
    {
        return trim_(s.substr(0, s.find(',')));
    }

    // 期待する origin の一覧。環境変数 PASSKEY_ORIGIN（カンマ区切り）があればそれ、
    // 無ければリクエストの Host から作る（このサーバ自身がページを配っている前提）。
    // Lambda やトンネルの後ろでは X-Forwarded-Proto / X-Forwarded-Host を見る。
    static inline std::vector<std::string> expected_origins(const Request& req)
    {
        std::vector<std::string> ret;
        std::string env = env_("PASSKEY_ORIGIN");
        if (env != "") {
            std::stringstream ss(env);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item = trim_(item);
                while (!item.empty() && item.back() == '/') item.pop_back();
                if (item != "") ret.push_back(item);
            }
            return ret;
        }
        std::string proto = first_of_list(req.get_header_value("X-Forwarded-Proto"));
        if (proto == "") proto = "http";
        std::string host = first_of_list(req.get_header_value("X-Forwarded-Host"));
        if (host == "") host = req.get_header_value("Host");
        ret.push_back(proto + "://" + host);
        return ret;
    }

    // rpId は環境変数 PASSKEY_RP_ID、無ければ最初の origin のホスト名（ポートは外す）
    static inline std::string expected_rp_id(const Request& req)
    {
        std::string env = env_("PASSKEY_RP_ID");
        if (env != "") return env;
        std::vector<std::string> o = expected_origins(req);
        std::string host = o.empty() ? "" : o[0];
        size_t p = host.find("://");
        if (p != std::string::npos) host = host.substr(p + 3);
        return host.substr(0, host.find(':'));
    }

    static inline std::string rp_name()
    {
        std::string env = env_("PASSKEY_RP_NAME");
        return env != "" ? env : "passkey_server_cpp";
    }

    //
    // authenticatorData / COSE_Key
    //

    struct AuthData {
        bytes rp_id_hash;
        int flags = 0;
        int64_t sign_count = 0;
        bool attested = false;
        bytes aaguid;
        bytes credential_id;
        bytes cose_key;
    };

    static inline AuthData parse_auth_data(const bytes& a)
    {
        AuthData r;
        if (a.size() < 37) throw PasskeyError("invalid request");
        r.rp_id_hash.assign(a.begin(), a.begin() + 32);
        r.flags = a[32];
        r.sign_count = ((int64_t)a[33] << 24) | (a[34] << 16) | (a[35] << 8) | a[36];
        if (r.flags & FLAG_AT) {
            size_t pos = 37;
            if (a.size() < pos + 18) throw PasskeyError("invalid request");
            r.aaguid.assign(a.begin() + pos, a.begin() + pos + 16);
            pos += 16;
            size_t n = (a[pos] << 8) | a[pos + 1];
            pos += 2;
            if (a.size() < pos + n) throw PasskeyError("invalid request");
            r.credential_id.assign(a.begin() + pos, a.begin() + pos + n);
            pos += n;
            Cbor key;
            size_t end = cbor_decode(a, pos, key);
            if (key.type != Cbor::MAP) throw PasskeyError("invalid request");
            r.cose_key.assign(a.begin() + pos, a.begin() + end);
            r.attested = true;
        }
        return r;
    }

    static inline void check_auth_data_common(const AuthData& ad, const std::string& rp_id)
    {
        if (ad.rp_id_hash != sha256(to_bytes(rp_id))) throw PasskeyError("rpIdHash mismatch");
        if (!(ad.flags & FLAG_UP)) throw PasskeyError("user presence not set");
        if (!(ad.flags & FLAG_UV)) throw PasskeyError("user verification not set");
    }

    // COSE_Key を読んで公開鍵として使えるか確かめ、alg を返す。対応は ES256(P-256) と RS256 だけ。
    // sig と data を渡すと署名も検証する（ok に結果）
    static inline int check_cose_key(const bytes& cose, const bytes* sig = nullptr,
                                     const bytes* data = nullptr, bool* ok = nullptr)
    {
        Cbor key;
        cbor_decode(cose, 0, key);
        if (key.type != Cbor::MAP) throw PasskeyError("unsupported algorithm");
        const Cbor* kty = key.get(1);
        const Cbor* alg = key.get(3);
        const Cbor* m1 = key.get(-1);
        const Cbor* m2 = key.get(-2);
        const Cbor* m3 = key.get(-3);
        auto is_int = [](const Cbor* c, int64_t v) { return c && c->is_int() && c->i == v; };
        auto is_bytes = [](const Cbor* c) { return c && c->type == Cbor::BYTES; };

        if (is_int(kty, 2) && is_int(alg, COSE_ALG_ES256) && is_int(m1, 1)) {
            if (!is_bytes(m2) || !is_bytes(m3) || m2->s.size() != 32 || m3->s.size() != 32) {
                throw PasskeyError("invalid public key");
            }
            bytes pt;
            pt.push_back(0x04);
            pt.insert(pt.end(), m2->s.begin(), m2->s.end());
            pt.insert(pt.end(), m3->s.begin(), m3->s.end());

            mbedtls_ecdsa_context ctx;
            mbedtls_ecdsa_init(&ctx);
            int r = mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
            if (r == 0) r = mbedtls_ecp_point_read_binary(&ctx.MBEDTLS_PRIVATE(grp),
                &ctx.MBEDTLS_PRIVATE(Q), pt.data(), pt.size());
            if (r == 0) r = mbedtls_ecp_check_pubkey(&ctx.MBEDTLS_PRIVATE(grp), &ctx.MBEDTLS_PRIVATE(Q));
            if (r != 0) {
                mbedtls_ecdsa_free(&ctx);
                throw PasskeyError("invalid public key");
            }
            if (sig) {
                bytes h = sha256(*data);
                *ok = mbedtls_ecdsa_read_signature(&ctx, h.data(), h.size(), sig->data(), sig->size()) == 0;
            }
            mbedtls_ecdsa_free(&ctx);
            return COSE_ALG_ES256;
        }
        if (is_int(kty, 3) && is_int(alg, COSE_ALG_RS256)) {
            if (!is_bytes(m1) || !is_bytes(m2) || m1->s.size() < 256) {
                throw PasskeyError("invalid public key");
            }
            bytes n(m1->s.begin(), m1->s.end());
            bytes e(m2->s.begin(), m2->s.end());

            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            int r = mbedtls_rsa_import_raw(&rsa, n.data(), n.size(), NULL, 0, NULL, 0, NULL, 0,
                e.data(), e.size());
            if (r == 0) r = mbedtls_rsa_complete(&rsa);
            if (r == 0) r = mbedtls_rsa_check_pubkey(&rsa);
            if (r == 0) r = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
            if (r != 0) {
                mbedtls_rsa_free(&rsa);
                throw PasskeyError("invalid public key");
            }
            if (sig) {
                bytes h = sha256(*data);
                *ok = sig->size() == mbedtls_rsa_get_len(&rsa) &&
                    mbedtls_rsa_pkcs1_verify(&rsa, MBEDTLS_MD_SHA256, (unsigned int)h.size(),
                        h.data(), sig->data()) == 0;
            }
            mbedtls_rsa_free(&rsa);
            return COSE_ALG_RS256;
        }
        throw PasskeyError("unsupported algorithm");
    }

    static inline std::string format_aaguid(const bytes& b)
    {
        std::string h = to_hex(b);
        return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" +
            h.substr(16, 4) + "-" + h.substr(20, 12);
    }

    //
    // clientDataJSON / チャレンジ
    //

    static inline json parse_client_data(const json& b64, bytes& raw)
    {
        raw = b64url_decode(b64);
        json cd;
        try {
            cd = json::parse(std::string(raw.begin(), raw.end()));
        }
        catch (...) {
            throw PasskeyError("invalid request");
        }
        if (!cd.is_object()) throw PasskeyError("invalid request");
        return cd;
    }

    static inline std::string str_of(const json& o, const char* key)
    {
        if (o.is_object() && o.contains(key) && o[key].is_string()) return o[key];
        return "";
    }

    static inline std::string new_challenge(sql::connection& db, const std::string& purpose,
                                            const std::string& user = "", const std::string& user_handle = "")
    {
        const auto tab = test::passkey::PasskeyChallenge{};
        // 期限切れのチャレンジを掃除してから発行する
        db(remove_from(tab).where(tab.expire < time_to_db(time(NULL))));
        std::string challenge = b64url_encode(random_bytes(32));
        db(insert_into(tab).set(tab.challenge = challenge, tab.purpose = purpose,
            tab.user = user, tab.userHandle = user_handle,
            tab.expire = time_to_db(time(NULL) + PASSKEY_CHALLENGE_EXPIRE_SECONDS),
            tab.createdAt = time_to_db(time(NULL))));
        return challenge;
    }

    struct ChallengeInfo {
        std::string user;
        std::string user_handle;
    };

    // clientData の challenge を引いて消す（1 回きり）。期限切れもここで弾く
    static inline ChallengeInfo consume_challenge(sql::connection& db, const json& cd, const std::string& purpose)
    {
        const auto tab = test::passkey::PasskeyChallenge{};
        std::string ch = str_of(cd, "challenge");
        if (ch == "") throw PasskeyError("challenge not found");
        ChallengeInfo info;
        std::string expire;
        int64_t id = -1;
        for (const auto& a : db(select(all_of(tab)).from(tab)
            .where(tab.challenge == ch and tab.purpose == purpose))) {
            id = a.id;
            info.user = a.user.value();
            info.user_handle = a.userHandle.value();
            expire = a.expire.value();
            break;
        }
        if (id < 0) throw PasskeyError("challenge not found");
        db(remove_from(tab).where(tab.id == id));
        if (db_to_time(expire) < time(NULL)) throw PasskeyError("challenge expired");
        return info;
    }

    static inline void check_origin(const json& cd, const Request& req)
    {
        std::vector<std::string> o = expected_origins(req);
        std::string origin = str_of(cd, "origin");
        bool found = cd.contains("origin") && cd["origin"].is_string() &&
            std::find(o.begin(), o.end(), origin) != o.end();
        if (!found) throw PasskeyError("origin mismatch");
        if (cd.contains("crossOrigin") && cd["crossOrigin"].is_boolean() && cd["crossOrigin"] == true) {
            throw PasskeyError("origin mismatch");
        }
    }

    //
    // account（一覧などは passkey テーブルの後ろ）
    //

    struct AccountRow {
        int64_t id = -1;
        std::string user, status, role, approved_by, approved_at, created_at;
        bool role_null = true;
        bool approved_by_null = true;
    };

    static inline bool get_account(sql::connection& db, const std::string& user, AccountRow& out)
    {
        const auto tab = test::passkey::Account{};
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.user == user))) {
            out.id = a.id;
            out.user = a.user.value();
            out.status = a.status.value();
            out.role_null = a.role.is_null();
            out.role = a.role.value();
            out.approved_by_null = a.approvedBy.is_null();
            out.approved_by = a.approvedBy.value();
            out.approved_at = a.approvedAt.value();
            out.created_at = a.createdAt.value();
            return true;
        }
        return false;
    }

    static inline bool account_exists(sql::connection& db, const std::string& user)
    {
        AccountRow a;
        return get_account(db, user, a);
    }

    static inline bool is_approved(sql::connection& db, const std::string& user)
    {
        AccountRow a;
        return get_account(db, user, a) && a.status == ACCOUNT_APPROVED;
    }

    static inline bool has_admin_request(sql::connection& db, const std::string& user)
    {
        const auto tab = test::passkey::AdminRequest{};
        return !db(select(tab.id).from(tab).where(tab.user == user)).empty();
    }

    // 承認済みなら role、承認待ちや存在しなければ null
    static inline json role_of(sql::connection& db, const std::string& user)
    {
        AccountRow a;
        if (!get_account(db, user, a) || a.status != ACCOUNT_APPROVED || a.role_null) return nullptr;
        return a.role;
    }

    static inline size_t admin_count(sql::connection& db)
    {
        const auto tab = test::passkey::Account{};
        size_t n = 0;
        for (const auto& a : db(select(tab.id).from(tab)
            .where(tab.status == ACCOUNT_APPROVED and tab.role == ROLE_ADMIN))) {
            (void)a;
            n++;
        }
        return n;
    }

    //
    // session
    //

    static inline std::string create_session(sql::connection& db, const std::string& user)
    {
        const auto tab = test::passkey::Session{};
        // 期限切れのセッションを掃除してから発行する
        db(remove_from(tab).where(tab.expire < time_to_db(time(NULL))));
        std::string skey = to_hex(random_bytes(16));
        db(insert_into(tab).set(tab.user = user, tab.skey = skey,
            tab.expire = time_to_db(time(NULL) + 3600 * SESSION_EXPIRE_HOURS),
            tab.createdAt = time_to_db(time(NULL))));
        return skey;
    }

    struct SessionInfo {
        int64_t id = -1;
        std::string user;
        std::string expire;
    };

    static inline SessionInfo get_session(sql::connection& db, const std::string& skey)
    {
        SessionInfo s;
        if (skey == "") return s;
        const auto tab = test::passkey::Session{};
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.skey == skey))) {
            if (db_to_time(a.expire.value()) < time(NULL)) break;
            s.id = a.id;
            s.user = a.user.value();
            s.expire = a.expire.value();
            break;
        }
        // アカウントが消されていればそのトークンも無効
        if (s.id >= 0 && !account_exists(db, s.user)) s = SessionInfo();
        return s;
    }

    static inline std::string session_user(sql::connection& db, const std::string& skey)
    {
        SessionInfo s = get_session(db, skey);
        if (s.id < 0) throw PasskeyError("not logged in");
        return s.user;
    }

    // 承認済みのユーザだけが使える API の入口
    static inline std::string approved_user(sql::connection& db, const std::string& skey)
    {
        std::string user = session_user(db, skey);
        if (!is_approved(db, user)) throw PasskeyError("not approved");
        return user;
    }

    // 全体の管理者だけが使える API の入口
    static inline std::string admin_user(sql::connection& db, const std::string& skey)
    {
        std::string user = approved_user(db, skey);
        if (role_of(db, user) != ROLE_ADMIN) throw PasskeyError("admin only");
        return user;
    }

    //
    // passkey テーブル
    //

    struct PasskeyRow {
        int64_t id = -1;
        std::string user, name, credential_id, user_handle, public_key, transports, aaguid;
        std::string last_used_at, created_at;
        int64_t alg = 0, sign_count = 0, backup_eligible = 0, backed_up = 0;
    };

    template <typename Row>
    static inline PasskeyRow to_row(const Row& a)
    {
        PasskeyRow r;
        r.id = a.id;
        r.user = a.user.value();
        r.name = a.name.value();
        r.credential_id = a.credentialId.value();
        r.user_handle = a.userHandle.value();
        r.public_key = a.publicKey.value();
        r.transports = a.transports.value();
        r.aaguid = a.aaguid.value();
        r.last_used_at = a.lastUsedAt.value();
        r.created_at = a.createdAt.value();
        r.alg = a.alg.value();
        r.sign_count = a.signCount.value();
        r.backup_eligible = a.backupEligible.value();
        r.backed_up = a.backedUp.value();
        return r;
    }

    static inline std::vector<std::string> split_transports(const std::string& s)
    {
        std::vector<std::string> v;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (item != "") v.push_back(item);
        }
        return v;
    }

    static inline json passkey_to_json(const PasskeyRow& p)
    {
        json o = json::object();
        o["user"] = p.user;
        o["name"] = p.name;
        o["credential_id"] = p.credential_id;
        o["user_handle"] = p.user_handle;
        o["alg"] = p.alg;
        o["public_key"] = p.public_key;
        o["sign_count"] = p.sign_count;
        o["transports"] = split_transports(p.transports);
        o["backup_eligible"] = p.backup_eligible;
        o["backed_up"] = p.backed_up;
        o["aaguid"] = p.aaguid;
        o["last_used_at"] = format_time(p.last_used_at);
        o["created_at"] = format_time(p.created_at);
        return o;
    }

    static inline bool get_passkey(sql::connection& db, const std::string& credential_id, PasskeyRow& out)
    {
        const auto tab = test::passkey::Passkey{};
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.credentialId == credential_id))) {
            out = to_row(a);
            return true;
        }
        return false;
    }

    static inline std::vector<PasskeyRow> get_user_passkeys(sql::connection& db, const std::string& user)
    {
        std::vector<PasskeyRow> v;
        const auto tab = test::passkey::Passkey{};
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.user == user).order_by(tab.id.asc()))) {
            v.push_back(to_row(a));
        }
        return v;
    }

    static inline json cred_descriptor(const PasskeyRow& p)
    {
        json d = json::object();
        d["type"] = "public-key";
        d["id"] = p.credential_id;
        std::vector<std::string> t = split_transports(p.transports);
        if (!t.empty()) d["transports"] = t;
        return d;
    }

    static inline void delete_account(sql::connection& db, const std::string& user)
    {
        const auto ptab = test::passkey::Passkey{};
        const auto stab = test::passkey::Session{};
        const auto atab = test::passkey::Account{};
        db(remove_from(ptab).where(ptab.user == user));
        db(remove_from(stab).where(stab.user == user));
        db(remove_from(atab).where(atab.user == user));
        const auto rtab = test::passkey::AdminRequest{};
        db(remove_from(rtab).where(rtab.user == user));
        // テナントのメンバーからも外す（テナント機能を外してビルドしたときは表が無いので無視）
        try {
            const auto mtab = test::tenant::TenantMember{};
            db(remove_from(mtab).where(mtab.user == user));
        }
        catch (...) {}
    }

    static inline json account_to_json(sql::connection& db, const AccountRow& a)
    {
        json o = json::object();
        o["user"] = a.user;
        o["status"] = a.status;
        o["role"] = a.role_null ? json(nullptr) : json(a.role);
        o["approved_by"] = a.approved_by_null ? json(nullptr) : json(a.approved_by);
        o["approved_at"] = format_time(a.approved_at);
        o["created_at"] = format_time(a.created_at);
        o["passkey_count"] = get_user_passkeys(db, a.user).size();
        return o;
    }

    // ユーザ名は 1〜64 バイト、制御文字なし
    static inline bool valid_user_name(const json& j)
    {
        if (!j.is_string()) return false;
        std::string s = j;
        if (s.empty() || s.size() > USER_NAME_MAX_BYTES) return false;
        for (unsigned char c : s) {
            if (c < 0x20 || c == 0x7f) return false;
        }
        return true;
    }

    //
    // API 本体
    //

    // トークン無し: body.user の新規アカウント（まだ誰も使っていない名前）
    // トークン有り: ログイン中のアカウントにパスキーを追加
    static inline json passkey_register_options(sql::connection& db, const json& body,
                                                const std::string& skey, const Request& req)
    {
        std::string user;
        if (skey != "") {
            user = session_user(db, skey);
        }
        else {
            if (!body.contains("user") || !valid_user_name(body["user"])) throw PasskeyError("invalid user name");
            user = body["user"];
        }
        if (skey == "" && account_exists(db, user)) throw PasskeyError("user already exists");
        std::vector<PasskeyRow> rows = get_user_passkeys(db, user);
        // 認証器に渡す user.id。アカウントごとに 1 つ、最初の登録時にランダムに作る
        // （ユーザ名などの個人情報は入れない）
        std::string handle = rows.empty() ? b64url_encode(random_bytes(32)) : rows[0].user_handle;
        std::string challenge = new_challenge(db, "register", user, handle);

        json exclude = json::array();
        for (auto& p : rows) exclude.push_back(cred_descriptor(p));

        json pk = json::object();
        pk["rp"] = { {"id", expected_rp_id(req)}, {"name", rp_name()} };
        pk["user"] = { {"id", handle}, {"name", user}, {"displayName", user} };
        pk["challenge"] = challenge;
        pk["pubKeyCredParams"] = json::array({
            { {"type", "public-key"}, {"alg", COSE_ALG_ES256} },
            { {"type", "public-key"}, {"alg", COSE_ALG_RS256} },
        });
        pk["timeout"] = PASSKEY_TIMEOUT_MS;
        pk["attestation"] = "none";
        pk["authenticatorSelection"] = {
            {"residentKey", "required"}, {"requireResidentKey", true}, {"userVerification", "required"},
        };
        pk["excludeCredentials"] = exclude;

        json ret = json::object();
        ret["status"] = "success";
        ret["publicKey"] = pk;
        return ret;
    }

    static inline json passkey_register_verify(sql::connection& db, const json& body,
                                               const std::string& skey, const Request& req)
    {
        std::string cred_id = str_of(body, "id");
        if (!body.contains("response") || !body["response"].is_object() || cred_id == "") {
            throw PasskeyError("invalid request");
        }
        const json& resp = body["response"];
        std::string login_user = skey != "" ? session_user(db, skey) : "";
        bytes raw_cd;
        json cd = parse_client_data(resp.contains("clientDataJSON") ? resp["clientDataJSON"] : json(), raw_cd);
        if (str_of(cd, "type") != "webauthn.create") throw PasskeyError("type mismatch");
        ChallengeInfo ch = consume_challenge(db, cd, "register");
        if (skey != "") {
            if (ch.user != login_user) throw PasskeyError("challenge user mismatch");
        }
        else if (account_exists(db, ch.user)) {
            // options の後で同じ名前が先に登録された
            throw PasskeyError("user already exists");
        }
        check_origin(cd, req);

        Cbor att;
        cbor_decode(b64url_decode(resp.contains("attestationObject") ? resp["attestationObject"] : json()), 0, att);
        const Cbor* ad_c = att.type == Cbor::MAP ? att.get(std::string("authData")) : nullptr;
        if (!ad_c || ad_c->type != Cbor::BYTES) throw PasskeyError("invalid request");
        AuthData ad = parse_auth_data(bytes(ad_c->s.begin(), ad_c->s.end()));
        check_auth_data_common(ad, expected_rp_id(req));
        if (!ad.attested) throw PasskeyError("attested credential data missing");
        if (b64url_encode(ad.credential_id) != cred_id) throw PasskeyError("credential id mismatch");
        int alg = check_cose_key(ad.cose_key);
        PasskeyRow dummy;
        if (get_passkey(db, cred_id, dummy)) throw PasskeyError("credential already registered");

        std::string transports;
        if (resp.contains("transports") && resp["transports"].is_array()) {
            for (auto& t : resp["transports"]) {
                if (!t.is_string()) continue;
                if (transports != "") transports += ",";
                transports += t.get<std::string>();
            }
        }
        std::string name = str_of(body, "name");
        if (name == "") name = "passkey";

        const auto tab = test::passkey::Passkey{};
        std::string now = time_to_db(time(NULL));
        db(insert_into(tab).set(tab.user = ch.user, tab.credentialId = cred_id,
            tab.userHandle = ch.user_handle, tab.publicKey = b64url_encode(ad.cose_key),
            tab.alg = alg, tab.signCount = ad.sign_count, tab.transports = transports,
            tab.backupEligible = (ad.flags & FLAG_BE) ? 1 : 0, tab.backedUp = (ad.flags & FLAG_BS) ? 1 : 0,
            tab.aaguid = format_aaguid(ad.aaguid), tab.name = name,
            tab.createdAt = now, tab.updatedAt = now));
        if (skey == "") {
            // 新規アカウント。全体の管理者がまだ誰もいなければ（＝最初の 1 人）全体の管理者、それ以外は一般
            const auto atab = test::passkey::Account{};
            bool first = admin_count(db) == 0;
            db(insert_into(atab).set(atab.user = ch.user, atab.status = ACCOUNT_APPROVED,
                atab.role = first ? ROLE_ADMIN : ROLE_MEMBER, atab.approvedBy = ch.user,
                atab.approvedAt = now, atab.createdAt = now));
        }

        PasskeyRow p;
        get_passkey(db, cred_id, p);
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = ch.user;
        ret["role"] = role_of(db, ch.user);
        ret["passkey"] = passkey_to_json(p);
        if (skey == "") {
            // 新規アカウントはそのままログイン状態にする
            ret["access_token"] = create_session(db, ch.user);
        }
        return ret;
    }

    static inline json passkey_login_options(sql::connection& db, const json& body,
                                             const std::string& skey, const Request& req)
    {
        std::string user = str_of(body, "user");
        json allow = json::array();
        if (user != "") {
            for (auto& p : get_user_passkeys(db, user)) allow.push_back(cred_descriptor(p));
        }
        std::string challenge = new_challenge(db, "login", user);
        json pk = json::object();
        pk["challenge"] = challenge;
        pk["rpId"] = expected_rp_id(req);
        pk["timeout"] = PASSKEY_TIMEOUT_MS;
        pk["userVerification"] = "required";
        pk["allowCredentials"] = allow;
        json ret = json::object();
        ret["status"] = "success";
        ret["publicKey"] = pk;
        return ret;
    }

    static inline json passkey_login_verify(sql::connection& db, const json& body,
                                            const std::string& skey, const Request& req)
    {
        std::string cred_id = str_of(body, "id");
        if (!body.contains("response") || !body["response"].is_object() || cred_id == "") {
            throw PasskeyError("invalid request");
        }
        const json& resp = body["response"];
        bytes raw_cd;
        json cd = parse_client_data(resp.contains("clientDataJSON") ? resp["clientDataJSON"] : json(), raw_cd);
        bytes auth_data = b64url_decode(resp.contains("authenticatorData") ? resp["authenticatorData"] : json());
        bytes signature = b64url_decode(resp.contains("signature") ? resp["signature"] : json());
        if (str_of(cd, "type") != "webauthn.get") throw PasskeyError("type mismatch");
        ChallengeInfo ch = consume_challenge(db, cd, "login");
        check_origin(cd, req);

        PasskeyRow p;
        if (!get_passkey(db, cred_id, p)) throw PasskeyError("unknown credential");
        if (ch.user != "" && ch.user != p.user) throw PasskeyError("challenge user mismatch");
        std::string uh = str_of(resp, "userHandle");
        if (uh != "" && uh != p.user_handle) throw PasskeyError("user handle mismatch");

        AuthData ad = parse_auth_data(auth_data);
        check_auth_data_common(ad, expected_rp_id(req));
        bytes data = auth_data;
        bytes h = sha256(raw_cd);
        data.insert(data.end(), h.begin(), h.end());
        bool ok = false;
        check_cose_key(b64url_decode(p.public_key), &signature, &data, &ok);
        if (!ok) throw PasskeyError("signature invalid");
        // 署名カウンタ。どちらも 0 なら（同期パスキーはだいたいそう）見ない
        if ((ad.sign_count != 0 || p.sign_count != 0) && ad.sign_count <= p.sign_count) {
            throw PasskeyError("sign count did not increase");
        }

        const auto tab = test::passkey::Passkey{};
        db(update(tab).set(tab.signCount = ad.sign_count, tab.backedUp = (ad.flags & FLAG_BS) ? 1 : 0,
            tab.lastUsedAt = time_to_db(time(NULL)), tab.updatedAt = time_to_db(time(NULL)))
            .where(tab.id == p.id));

        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = p.user;
        ret["role"] = role_of(db, p.user);
        ret["access_token"] = create_session(db, p.user);
        return ret;
    }

    static inline json passkey_me(sql::connection& db, const json& body,
                                  const std::string& skey, const Request& req)
    {
        SessionInfo s = get_session(db, skey);
        if (s.id < 0) throw PasskeyError("not logged in");
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = s.user;
        ret["role"] = role_of(db, s.user);
        ret["admin_requested"] = has_admin_request(db, s.user);
        ret["expire"] = format_time(s.expire);
        return ret;
    }

    static inline json passkey_logout(sql::connection& db, const json& body,
                                      const std::string& skey, const Request& req)
    {
        SessionInfo s = get_session(db, skey);
        if (s.id < 0) throw PasskeyError("not logged in");
        const auto tab = test::passkey::Session{};
        db(remove_from(tab).where(tab.id == s.id));
        json ret = json::object();
        ret["status"] = "success";
        return ret;
    }

    static inline json passkey_list(sql::connection& db, const json& body,
                                    const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        std::vector<PasskeyRow> rows = get_user_passkeys(db, user);
        json list = json::array();
        for (auto& p : rows) list.push_back(passkey_to_json(p));
        json columns = json::array();
        for (const char* c : PASSKEY_COLUMNS) columns.push_back({ {"field", c}, {"title", c} });
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = user;
        ret["passkey_list"] = list;
        ret["columns"] = columns;
        ret["total_count"] = rows.size();
        return ret;
    }

    // 最後の 1 本を消すとそのアカウントには二度と入れないので、アカウントごと消す（＝退会）
    static inline json passkey_delete(sql::connection& db, const json& body,
                                      const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        std::string cred_id = str_of(body, "credential_id");
        if (cred_id == "") throw PasskeyError("invalid request");
        PasskeyRow p;
        if (!get_passkey(db, cred_id, p) || p.user != user) throw PasskeyError("unknown credential");
        // 最後の管理者が退会すると誰も承認できなくなるので止める
        if (get_user_passkeys(db, user).size() == 1 && role_of(db, user) == ROLE_ADMIN && admin_count(db) == 1) {
            throw PasskeyError("last admin cannot leave");
        }
        const auto tab = test::passkey::Passkey{};
        db(remove_from(tab).where(tab.id == p.id));
        bool account_deleted = get_user_passkeys(db, user).empty();
        if (account_deleted) delete_account(db, user);
        json ret = json::object();
        ret["status"] = "success";
        ret["credential_id"] = cred_id;
        ret["account_deleted"] = account_deleted;
        return ret;
    }

    static inline json account_list(sql::connection& db, const json& body,
                                    const std::string& skey, const Request& req)
    {
        std::string user = admin_user(db, skey);
        const auto tab = test::passkey::Account{};
        std::vector<std::string> users;
        for (const auto& a : db(select(tab.user).from(tab).unconditionally().order_by(tab.id.asc()))) {
            users.push_back(a.user.value());
        }
        json list = json::array();
        for (auto& u : users) {
            AccountRow a;
            if (get_account(db, u, a)) list.push_back(account_to_json(db, a));
        }
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = user;
        ret["account_list"] = list;
        ret["total_count"] = list.size();
        return ret;
    }

    // {user}。全体の管理者を一般に戻す（自分でもよい）。全体の管理者が 1 人もいなくなる変更はできない
    static inline json account_demote(sql::connection& db, const json& body,
                                      const std::string& skey, const Request& req)
    {
        admin_user(db, skey);
        std::string target = str_of(body, "user");
        if (target == "") throw PasskeyError("invalid request");
        AccountRow a;
        if (!get_account(db, target, a)) throw PasskeyError("unknown account");
        if (a.role != ROLE_ADMIN) throw PasskeyError("not an admin");
        if (admin_count(db) == 1) throw PasskeyError("last admin cannot be demoted");
        const auto tab = test::passkey::Account{};
        db(update(tab).set(tab.role = ROLE_MEMBER).where(tab.id == a.id));
        get_account(db, target, a);
        json ret = json::object();
        ret["status"] = "success";
        ret["account"] = account_to_json(db, a);
        return ret;
    }

    //
    // 全体の管理者への申請
    //

    static inline json admin_request_to_json(sql::connection& db, const std::string& user, const std::string& created_at)
    {
        json o = json::object();
        o["user"] = user;
        o["created_at"] = format_time(created_at);
        o["passkey_count"] = get_user_passkeys(db, user).size();
        return o;
    }

    static inline json account_admin_request(sql::connection& db, const json& body,
                                             const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        if (role_of(db, user) == ROLE_ADMIN) throw PasskeyError("already admin");
        if (has_admin_request(db, user)) throw PasskeyError("already requested");
        std::string now = time_to_db(time(NULL));
        const auto tab = test::passkey::AdminRequest{};
        db(insert_into(tab).set(tab.user = user, tab.createdAt = now));
        json ret = json::object();
        ret["status"] = "success";
        ret["request"] = admin_request_to_json(db, user, now);
        return ret;
    }

    static inline json account_admin_request_cancel(sql::connection& db, const json& body,
                                                    const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        if (!has_admin_request(db, user)) throw PasskeyError("unknown request");
        const auto tab = test::passkey::AdminRequest{};
        db(remove_from(tab).where(tab.user == user));
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = user;
        return ret;
    }

    static inline json account_admin_requests(sql::connection& db, const json& body,
                                              const std::string& skey, const Request& req)
    {
        admin_user(db, skey);
        const auto tab = test::passkey::AdminRequest{};
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& a : db(select(all_of(tab)).from(tab).unconditionally().order_by(tab.id.asc()))) {
            rows.push_back(std::make_pair(a.user.value(), a.createdAt.value()));
        }
        json list = json::array();
        for (auto& r : rows) list.push_back(admin_request_to_json(db, r.first, r.second));
        json ret = json::object();
        ret["status"] = "success";
        ret["request_list"] = list;
        ret["total_count"] = list.size();
        return ret;
    }

    static inline json account_admin_approve(sql::connection& db, const json& body,
                                             const std::string& skey, const Request& req)
    {
        std::string user = admin_user(db, skey);
        std::string target = str_of(body, "user");
        if (target == "") throw PasskeyError("invalid request");
        if (!has_admin_request(db, target)) throw PasskeyError("unknown request");
        const auto rtab = test::passkey::AdminRequest{};
        const auto atab = test::passkey::Account{};
        db(remove_from(rtab).where(rtab.user == target));
        db(update(atab).set(atab.role = ROLE_ADMIN, atab.approvedBy = user,
            atab.approvedAt = time_to_db(time(NULL))).where(atab.user == target));
        AccountRow a;
        get_account(db, target, a);
        json ret = json::object();
        ret["status"] = "success";
        ret["account"] = account_to_json(db, a);
        return ret;
    }

    static inline json account_admin_reject(sql::connection& db, const json& body,
                                            const std::string& skey, const Request& req)
    {
        admin_user(db, skey);
        std::string target = str_of(body, "user");
        if (target == "") throw PasskeyError("invalid request");
        if (!has_admin_request(db, target)) throw PasskeyError("unknown request");
        const auto tab = test::passkey::AdminRequest{};
        db(remove_from(tab).where(tab.user == target));
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = target;
        return ret;
    }

    // 自分以外のアカウントを消す（管理者も消せる。自分は消せないので管理者は 1 人以上残る）。
    // 自分のは passkey/delete で最後の 1 本を消す（退会）
    static inline json account_delete(sql::connection& db, const json& body,
                                      const std::string& skey, const Request& req)
    {
        std::string user = admin_user(db, skey);
        std::string target = str_of(body, "user");
        if (target == "") throw PasskeyError("invalid request");
        if (target == user) throw PasskeyError("cannot delete yourself");
        if (!account_exists(db, target)) throw PasskeyError("unknown account");
        delete_account(db, target);
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = target;
        return ret;
    }

    //
    // テーブル作成と routes
    //

    static inline void init_passkey_db()
    {
        sql::connection& db = get_sql_connection();
#ifdef USE_MYSQL
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS passkey (
        id int PRIMARY KEY AUTO_INCREMENT,
        user TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        user_handle TEXT NOT NULL,
        public_key TEXT NOT NULL,
        alg int NOT NULL,
        sign_count bigint NOT NULL,
        transports TEXT,
        backup_eligible int,
        backed_up int,
        aaguid TEXT,
        name TEXT,
        last_used_at DateTime,
        created_at DateTime default current_timestamp,
        updated_at DateTime default current_timestamp on update current_timestamp)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS passkey_challenge (
        id int PRIMARY KEY AUTO_INCREMENT,
        challenge TEXT NOT NULL,
        purpose TEXT NOT NULL,
        user TEXT,
        user_handle TEXT,
        expire DateTime NOT NULL,
        created_at DateTime default current_timestamp)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS session (
        id int PRIMARY KEY AUTO_INCREMENT,
        user TEXT NOT NULL,
        skey TEXT NOT NULL,
        expire DateTime NOT NULL,
        created_at DateTime default current_timestamp)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS account (
        id int PRIMARY KEY AUTO_INCREMENT,
        user TEXT NOT NULL,
        status TEXT NOT NULL,
        role TEXT,
        approved_by TEXT,
        approved_at DateTime,
        created_at DateTime)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS admin_request (
        id int PRIMARY KEY AUTO_INCREMENT,
        user TEXT NOT NULL,
        created_at DateTime)
        )");
#else
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS passkey (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        user_handle TEXT NOT NULL,
        public_key TEXT NOT NULL,
        alg INTEGER NOT NULL,
        sign_count INTEGER NOT NULL,
        transports TEXT,
        backup_eligible INTEGER,
        backed_up INTEGER,
        aaguid TEXT,
        name TEXT,
        last_used_at TEXT,
        created_at TEXT,
        updated_at TEXT)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS passkey_challenge (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        challenge TEXT NOT NULL,
        purpose TEXT NOT NULL,
        user TEXT,
        user_handle TEXT,
        expire TEXT NOT NULL,
        created_at TEXT)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS session (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        skey TEXT NOT NULL,
        expire TEXT NOT NULL,
        created_at TEXT)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS account (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        status TEXT NOT NULL,
        role TEXT,
        approved_by TEXT,
        approved_at TEXT,
        created_at TEXT)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS admin_request (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        created_at TEXT)
        )");
#endif
        // role 列が無かった頃の account テーブルには列を足す（既にあればエラーになるので無視）
        try {
            db.execute("ALTER TABLE account ADD COLUMN role TEXT");
        }
        catch (...) {}
        // account テーブルが無かった頃に登録した人は、承認済みのアカウントとして引き継ぐ
        db.execute("INSERT INTO account (user, status, created_at) "
            "SELECT DISTINCT user, 'approved', '" + time_to_db(time(NULL)) + "' FROM passkey "
            "WHERE user NOT IN (SELECT user FROM account)");
        // role が無かった頃の承認済みは、許可も削除もできたので管理者として引き継ぐ
        db.execute("UPDATE account SET role = 'admin' WHERE status = 'approved' AND role IS NULL");
        // 全体の承認待ちは無くなったので、承認待ちだった人は一般のアカウントにする
        db.execute("UPDATE account SET status = 'approved', role = 'member' WHERE status = 'pending'");
    }

    typedef json(*api_func)(sql::connection&, const json&, const std::string&, const Request&);

    // DB は 1 本の接続を共有しているので、API 1 回分を丸ごと排他にする
    // （チャレンジの「引いて消す」を 2 つのリクエストが同時にやらないように）
    static inline void run(api_func f, const Request& req, Response& res)
    {
        static std::mutex mtx;
        std::string auth = get_auth(req);
        if (auth == "error") auth = "";
        json body = get_request(req);
        if (!body.is_object()) body = json::object();
        json ret;
        {
            std::lock_guard<std::mutex> lock(mtx);
            try {
                ret = f(get_sql_connection(), body, auth, req);
            }
            catch (const PasskeyError& e) {
                ret = { {"status", "fail"}, {"message", e.what()} };
            }
            catch (const std::exception& e) {
                fprintf(stderr, "#### passkey error: %s\n", e.what());
                ret = { {"status", "fail"}, {"message", "invalid request"} };
            }
            catch (...) {
                ret = { {"status", "fail"}, {"message", "invalid request"} };
            }
        }
        res.set_content(get_response(ret), "application/json");
        common_response(req, res);
    }

    static inline void add_route(Server& svr, const std::string& path, api_func f)
    {
        svr.Post(path, [f](const Request& req, Response& res) { run(f, req, res); });
        svr.Options(path, [](const Request& req, Response& res) { common_response(req, res); });
    }

    inline static void init_api_passkey(Server& svr)
    {
        init_passkey_db();
        add_route(svr, "/api/passkey/v0/register_options", passkey_register_options);
        add_route(svr, "/api/passkey/v0/register_verify", passkey_register_verify);
        add_route(svr, "/api/passkey/v0/login_options", passkey_login_options);
        add_route(svr, "/api/passkey/v0/login_verify", passkey_login_verify);
        add_route(svr, "/api/passkey/v0/me", passkey_me);
        add_route(svr, "/api/passkey/v0/logout", passkey_logout);
        add_route(svr, "/api/passkey/v0/list", passkey_list);
        add_route(svr, "/api/passkey/v0/delete", passkey_delete);
        add_route(svr, "/api/account/v0/list", account_list);
        add_route(svr, "/api/account/v0/demote", account_demote);
        add_route(svr, "/api/account/v0/admin_request", account_admin_request);
        add_route(svr, "/api/account/v0/admin_request_cancel", account_admin_request_cancel);
        add_route(svr, "/api/account/v0/admin_requests", account_admin_requests);
        add_route(svr, "/api/account/v0/admin_approve", account_admin_approve);
        add_route(svr, "/api/account/v0/admin_reject", account_admin_reject);
        add_route(svr, "/api/account/v0/delete", account_delete);
        svr.Get("/", [](const Request& req, Response& res) {
            res.set_redirect("/html/index.html");
            });
    }

}

#endif
