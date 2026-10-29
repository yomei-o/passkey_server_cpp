#ifndef API_TENANT_H_
#define API_TENANT_H_

//
// テナントと、テナントごとの電気のスイッチ
//
// テナントは guid（ランダムな 32 桁の 16 進数）で指定する。ページの URL は /html/index.html?tenant=<guid>。
// 全体の管理者がテナントを追加して、その URL をテナントの人に渡す。
//
//   /api/tenant/v0/get          {tenant} のテナント名と自分の立場（ログインしていなくても名前は見える。
//                               電気の状態は承認済みメンバーにだけ見せる）
//   /api/tenant/v0/list         全体の管理者は全テナント、それ以外は自分が参加（申請）しているテナント
//   /api/tenant/v0/add          テナントを追加する（全体の管理者だけ）
//   /api/tenant/v0/delete       テナントを消す（全体の管理者だけ。メンバーと電気も消える）
//
//   /api/tenant/v0/join         テナントに参加申請する（ログインしていれば誰でも）
//   /api/tenant/v0/leave        テナントを抜ける（申請の取り下げも）
//   /api/tenant/v0/members      テナントのメンバー一覧（そのテナントの承認済みメンバーだけ）
//   /api/tenant/v0/approve      申請を管理者 / 一般として承認する（そのテナントの管理者だけ）
//   /api/tenant/v0/remove       自分以外のメンバーを外す（そのテナントの管理者だけ。承認待ちなら却下）
//   /api/tenant/v0/switch_set   テナントの電気を切り替える（そのテナントの承認済みメンバーだけ）
//
// テナントに管理者がいないときに参加申請した人（＝最初の 1 人）は、そのまま承認済みの管理者になる。
// Python 版は python/testsv_api_tenant.py。検査の順番と失敗時の message を揃えてある。
//

#include "testsv_api_passkey.h"
#include "model_tenant.h"
#include "model_switch.h"

namespace tenant_api {

    using namespace passkey;

    static inline std::string switch_name(const std::string& guid)
    {
        return "tenant/" + guid;
    }

    struct TenantRow {
        int64_t id = -1;
        std::string guid, name, created_by, created_at;
        bool created_by_null = true;
    };

    struct MemberRow {
        int64_t id = -1;
        std::string user, status, role, approved_by, approved_at, created_at;
        bool role_null = true, approved_by_null = true;
    };

    template <typename Row>
    static inline TenantRow to_tenant(const Row& a)
    {
        TenantRow t;
        t.id = a.id;
        t.guid = a.guid.value();
        t.name = a.name.value();
        t.created_by_null = a.createdBy.is_null();
        t.created_by = a.createdBy.value();
        t.created_at = a.createdAt.value();
        return t;
    }

    static inline TenantRow get_tenant(sql::connection& db, const json& body)
    {
        std::string guid = str_of(body, "tenant");
        if (guid == "") throw PasskeyError("invalid request");
        const auto tab = test::tenant::Tenant{};
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.guid == guid))) {
            return to_tenant(a);
        }
        throw PasskeyError("unknown tenant");
    }

    static inline bool get_member(sql::connection& db, int64_t tenant_id, const std::string& user, MemberRow& out)
    {
        const auto tab = test::tenant::TenantMember{};
        for (const auto& a : db(select(all_of(tab)).from(tab)
            .where(tab.tenantId == tenant_id and tab.user == user))) {
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

    template <typename Row>
    static inline MemberRow to_member(const Row& a)
    {
        MemberRow m;
        m.id = a.id;
        m.user = a.user.value();
        m.status = a.status.value();
        m.role_null = a.role.is_null();
        m.role = a.role.value();
        m.approved_by_null = a.approvedBy.is_null();
        m.approved_by = a.approvedBy.value();
        m.approved_at = a.approvedAt.value();
        m.created_at = a.createdAt.value();
        return m;
    }

    static inline size_t count_members(sql::connection& db, int64_t tenant_id, bool approved_only,
                                       bool admin_only = false, const std::string& except_user = "")
    {
        const auto tab = test::tenant::TenantMember{};
        size_t n = 0;
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.tenantId == tenant_id))) {
            if (approved_only && a.status.value() != ACCOUNT_APPROVED) continue;
            if (admin_only && a.role.value() != ROLE_ADMIN) continue;
            if (except_user != "" && a.user.value() == except_user) continue;
            n++;
        }
        return n;
    }

    static inline size_t tenant_admin_count(sql::connection& db, int64_t tenant_id)
    {
        return count_members(db, tenant_id, true, true);
    }

    static inline json member_to_json(const MemberRow& m)
    {
        json o = json::object();
        o["user"] = m.user;
        o["status"] = m.status;
        o["role"] = m.role_null ? json(nullptr) : json(m.role);
        o["approved_by"] = m.approved_by_null ? json(nullptr) : json(m.approved_by);
        o["approved_at"] = format_time(m.approved_at);
        o["created_at"] = format_time(m.created_at);
        return o;
    }

    // そのテナントの承認済みメンバーだけ
    static inline MemberRow tenant_member_of(sql::connection& db, int64_t tenant_id, const std::string& user)
    {
        MemberRow m;
        if (!get_member(db, tenant_id, user, m) || m.status != ACCOUNT_APPROVED) {
            throw PasskeyError("tenant member only");
        }
        return m;
    }

    // そのテナントの管理者だけ
    static inline MemberRow tenant_admin_of(sql::connection& db, int64_t tenant_id, const std::string& user)
    {
        MemberRow m;
        if (!get_member(db, tenant_id, user, m) || m.status != ACCOUNT_APPROVED || m.role != ROLE_ADMIN) {
            throw PasskeyError("tenant admin only");
        }
        return m;
    }

    // 電気の状態はそのテナントの承認済みメンバーにだけ見せる（他は null）。user は空でもよい
    static inline json tenant_to_json(sql::connection& db, const TenantRow& t, const std::string& user)
    {
        MemberRow m;
        bool is_member = user != "" && get_member(db, t.id, user, m);
        json o = json::object();
        o["tenant"] = t.guid;
        o["name"] = t.name;
        o["created_by"] = t.created_by_null ? json(nullptr) : json(t.created_by);
        o["created_at"] = format_time(t.created_at);
        o["member_count"] = count_members(db, t.id, true);
        o["my_status"] = is_member ? json(m.status) : json(nullptr);
        o["my_role"] = is_member && !m.role_null ? json(m.role) : json(nullptr);
        o["on"] = nullptr;
        o["updated_by"] = nullptr;
        o["updated_at"] = nullptr;
        if (is_member && m.status == ACCOUNT_APPROVED) {
            o["on"] = false;
            const auto tab = test::switch_state::SwitchState{};
            for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.name == switch_name(t.guid)))) {
                o["on"] = a.value.value() == 1;
                o["updated_by"] = a.updatedBy.is_null() ? json(nullptr) : json(a.updatedBy.value());
                o["updated_at"] = format_time(a.updatedAt.value());
                break;
            }
        }
        return o;
    }

    //
    // テナント
    //

    // ログインしていなくてもテナント名は見える（URL を開いた人に何のテナントか見せるため）
    static inline json tenant_get(sql::connection& db, const json& body,
                                  const std::string& skey, const Request& req)
    {
        std::string user;
        if (skey != "") user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        json ret = json::object();
        ret["status"] = "success";
        ret["tenant"] = tenant_to_json(db, t, user);
        return ret;
    }

    static inline json tenant_list(sql::connection& db, const json& body,
                                   const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        bool admin = role_of(db, user) == ROLE_ADMIN;
        const auto tab = test::tenant::Tenant{};
        std::vector<TenantRow> rows;
        for (const auto& a : db(select(all_of(tab)).from(tab).unconditionally().order_by(tab.id.asc()))) {
            rows.push_back(to_tenant(a));
        }
        json list = json::array();
        for (auto& t : rows) {
            MemberRow m;
            if (admin || get_member(db, t.id, user, m)) list.push_back(tenant_to_json(db, t, user));
        }
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = user;
        ret["tenant_list"] = list;
        ret["total_count"] = list.size();
        return ret;
    }

    // テナント名はユーザ名と同じ規則（1〜64 バイト、制御文字なし）。同じ名前は作れない
    static inline json tenant_add(sql::connection& db, const json& body,
                                  const std::string& skey, const Request& req)
    {
        std::string user = admin_user(db, skey);
        if (!body.contains("name") || !valid_user_name(body["name"])) throw PasskeyError("invalid tenant name");
        std::string name = body["name"];
        const auto tab = test::tenant::Tenant{};
        if (!db(select(tab.id).from(tab).where(tab.name == name)).empty()) {
            throw PasskeyError("tenant already exists");
        }
        std::string guid = to_hex(random_bytes(16));
        db(insert_into(tab).set(tab.guid = guid, tab.name = name, tab.createdBy = user,
            tab.createdAt = time_to_db(time(NULL))));
        json b = json::object();
        b["tenant"] = guid;
        TenantRow t = get_tenant(db, b);
        json ret = json::object();
        ret["status"] = "success";
        ret["tenant"] = tenant_to_json(db, t, user);
        return ret;
    }

    static inline json tenant_delete(sql::connection& db, const json& body,
                                     const std::string& skey, const Request& req)
    {
        admin_user(db, skey);
        TenantRow t = get_tenant(db, body);
        const auto mtab = test::tenant::TenantMember{};
        const auto stab = test::switch_state::SwitchState{};
        const auto ttab = test::tenant::Tenant{};
        db(remove_from(mtab).where(mtab.tenantId == t.id));
        db(remove_from(stab).where(stab.name == switch_name(t.guid)));
        db(remove_from(ttab).where(ttab.id == t.id));
        json ret = json::object();
        ret["status"] = "success";
        ret["tenant"] = t.guid;
        return ret;
    }

    //
    // メンバー
    //

    static inline json tenant_join(sql::connection& db, const json& body,
                                   const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        MemberRow m;
        if (get_member(db, t.id, user, m)) throw PasskeyError("already requested");
        // このテナントに管理者がまだいなければ（＝最初の 1 人）そのまま承認済みの管理者
        bool first = tenant_admin_count(db, t.id) == 0;
        std::string now = time_to_db(time(NULL));
        const auto tab = test::tenant::TenantMember{};
        if (first) {
            db(insert_into(tab).set(tab.tenantId = t.id, tab.user = user, tab.status = ACCOUNT_APPROVED,
                tab.role = ROLE_ADMIN, tab.approvedBy = user, tab.approvedAt = now, tab.createdAt = now));
        }
        else {
            db(insert_into(tab).set(tab.tenantId = t.id, tab.user = user, tab.status = ACCOUNT_PENDING,
                tab.createdAt = now));
        }
        get_member(db, t.id, user, m);
        json ret = json::object();
        ret["status"] = "success";
        ret["member"] = member_to_json(m);
        return ret;
    }

    // 抜ける（承認待ちなら取り下げ）。最後の管理者は、他にメンバーがいる間は抜けられない
    static inline json tenant_leave(sql::connection& db, const json& body,
                                    const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        MemberRow m;
        if (!get_member(db, t.id, user, m)) throw PasskeyError("unknown member");
        size_t others = count_members(db, t.id, false, false, user);
        if (m.status == ACCOUNT_APPROVED && m.role == ROLE_ADMIN && tenant_admin_count(db, t.id) == 1 && others > 0) {
            throw PasskeyError("last admin cannot leave");
        }
        const auto tab = test::tenant::TenantMember{};
        db(remove_from(tab).where(tab.id == m.id));
        json ret = json::object();
        ret["status"] = "success";
        ret["tenant"] = t.guid;
        return ret;
    }

    static inline json tenant_members(sql::connection& db, const json& body,
                                      const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        MemberRow me = tenant_member_of(db, t.id, user);
        const auto tab = test::tenant::TenantMember{};
        json list = json::array();
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.tenantId == t.id).order_by(tab.id.asc()))) {
            list.push_back(member_to_json(to_member(a)));
        }
        json ret = json::object();
        ret["status"] = "success";
        ret["tenant"] = t.guid;
        ret["me"] = member_to_json(me);
        ret["member_list"] = list;
        ret["total_count"] = list.size();
        return ret;
    }

    // {tenant, user, role}。role は "admin"（管理者）か "member"（一般）
    static inline json tenant_approve(sql::connection& db, const json& body,
                                      const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        tenant_admin_of(db, t.id, user);
        std::string target = str_of(body, "user");
        if (target == "") throw PasskeyError("invalid request");
        std::string role = str_of(body, "role");
        if (role != ROLE_ADMIN && role != ROLE_MEMBER) throw PasskeyError("invalid role");
        MemberRow m;
        if (!get_member(db, t.id, target, m)) throw PasskeyError("unknown member");
        if (m.status == ACCOUNT_APPROVED) throw PasskeyError("already approved");
        const auto tab = test::tenant::TenantMember{};
        db(update(tab).set(tab.status = ACCOUNT_APPROVED, tab.role = role, tab.approvedBy = user,
            tab.approvedAt = time_to_db(time(NULL))).where(tab.id == m.id));
        get_member(db, t.id, target, m);
        json ret = json::object();
        ret["status"] = "success";
        ret["member"] = member_to_json(m);
        return ret;
    }

    // 自分以外を外す（承認待ちなら却下）。自分は外せないので、そのテナントの管理者は 1 人以上残る
    static inline json tenant_remove(sql::connection& db, const json& body,
                                     const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        tenant_admin_of(db, t.id, user);
        std::string target = str_of(body, "user");
        if (target == "") throw PasskeyError("invalid request");
        if (target == user) throw PasskeyError("cannot delete yourself");
        MemberRow m;
        if (!get_member(db, t.id, target, m)) throw PasskeyError("unknown member");
        const auto tab = test::tenant::TenantMember{};
        db(remove_from(tab).where(tab.id == m.id));
        json ret = json::object();
        ret["status"] = "success";
        ret["user"] = target;
        return ret;
    }

    static inline json tenant_switch_set(sql::connection& db, const json& body,
                                         const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        TenantRow t = get_tenant(db, body);
        tenant_member_of(db, t.id, user);
        if (!body.contains("on") || !body["on"].is_boolean()) throw PasskeyError("invalid request");
        int value = body["on"].get<bool>() ? 1 : 0;
        std::string now = time_to_db(time(NULL));
        std::string name = switch_name(t.guid);
        const auto tab = test::switch_state::SwitchState{};
        if (!db(select(tab.id).from(tab).where(tab.name == name)).empty()) {
            db(update(tab).set(tab.value = value, tab.updatedBy = user, tab.updatedAt = now)
                .where(tab.name == name));
        }
        else {
            db(insert_into(tab).set(tab.name = name, tab.value = value, tab.updatedBy = user, tab.updatedAt = now));
        }
        json ret = json::object();
        ret["status"] = "success";
        ret["tenant"] = tenant_to_json(db, t, user);
        return ret;
    }

    //
    // テーブル作成と routes
    //

    static inline void init_tenant_db()
    {
        sql::connection& db = get_sql_connection();
#ifdef USE_MYSQL
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS tenant (
        id int PRIMARY KEY AUTO_INCREMENT,
        guid TEXT NOT NULL,
        name TEXT NOT NULL,
        created_by TEXT,
        created_at DateTime)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS tenant_member (
        id int PRIMARY KEY AUTO_INCREMENT,
        tenant_id int NOT NULL,
        user TEXT NOT NULL,
        status TEXT NOT NULL,
        role TEXT,
        approved_by TEXT,
        approved_at DateTime,
        created_at DateTime)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS switch_state (
        id int PRIMARY KEY AUTO_INCREMENT,
        name TEXT NOT NULL,
        value int NOT NULL,
        updated_by TEXT,
        updated_at DateTime)
        )");
#else
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS tenant (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guid TEXT NOT NULL,
        name TEXT NOT NULL,
        created_by TEXT,
        created_at TEXT)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS tenant_member (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER NOT NULL,
        user TEXT NOT NULL,
        status TEXT NOT NULL,
        role TEXT,
        approved_by TEXT,
        approved_at TEXT,
        created_at TEXT)
        )");
        db.execute(R"(
        CREATE TABLE IF NOT EXISTS switch_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        value INTEGER NOT NULL,
        updated_by TEXT,
        updated_at TEXT)
        )");
#endif
    }

    inline static void init_api_tenant(Server& svr)
    {
        init_tenant_db();
        add_route(svr, "/api/tenant/v0/get", tenant_get);
        add_route(svr, "/api/tenant/v0/list", tenant_list);
        add_route(svr, "/api/tenant/v0/add", tenant_add);
        add_route(svr, "/api/tenant/v0/delete", tenant_delete);
        add_route(svr, "/api/tenant/v0/join", tenant_join);
        add_route(svr, "/api/tenant/v0/leave", tenant_leave);
        add_route(svr, "/api/tenant/v0/members", tenant_members);
        add_route(svr, "/api/tenant/v0/approve", tenant_approve);
        add_route(svr, "/api/tenant/v0/remove", tenant_remove);
        add_route(svr, "/api/tenant/v0/switch_set", tenant_switch_set);
    }

}

#endif
