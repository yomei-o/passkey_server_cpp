#ifndef API_SWITCH_H_
#define API_SWITCH_H_

//
// みんなの電気のスイッチ（パスキーでログインした人だけが切り替えられる）
//
//   /api/switch/v0/get    いまの状態。誰でも見られる
//   /api/switch/v0/set    {on: true/false} で切り替える。要ログイン
//
// Python 版は python/testsv_api_switch.py。
//

#include "testsv_api_passkey.h"
#include "model_switch.h"

namespace switch_api {

    using namespace passkey;

    static const char* const SWITCH_NAME = "light";

    static inline json switch_state(sql::connection& db)
    {
        const auto tab = test::switch_state::SwitchState{};
        json ret = json::object();
        ret["status"] = "success";
        ret["on"] = false;
        ret["updated_by"] = nullptr;
        ret["updated_at"] = nullptr;
        for (const auto& a : db(select(all_of(tab)).from(tab).where(tab.name == SWITCH_NAME))) {
            ret["on"] = a.value.value() == 1;
            ret["updated_by"] = a.updatedBy.is_null() ? json(nullptr) : json(a.updatedBy.value());
            ret["updated_at"] = format_time(a.updatedAt.value());
            break;
        }
        return ret;
    }

    static inline json switch_get(sql::connection& db, const json& body,
                                  const std::string& skey, const Request& req)
    {
        return switch_state(db);
    }

    static inline json switch_set(sql::connection& db, const json& body,
                                  const std::string& skey, const Request& req)
    {
        std::string user = session_user(db, skey);
        if (!body.contains("on") || !body["on"].is_boolean()) throw PasskeyError("invalid request");
        int value = body["on"].get<bool>() ? 1 : 0;
        std::string now = time_to_db(time(NULL));

        const auto tab = test::switch_state::SwitchState{};
        bool exists = false;
        for (const auto& a : db(select(tab.id).from(tab).where(tab.name == SWITCH_NAME))) {
            exists = true;
            break;
        }
        if (exists) {
            db(update(tab).set(tab.value = value, tab.updatedBy = user, tab.updatedAt = now)
                .where(tab.name == SWITCH_NAME));
        }
        else {
            db(insert_into(tab).set(tab.name = SWITCH_NAME, tab.value = value,
                tab.updatedBy = user, tab.updatedAt = now));
        }
        return switch_state(db);
    }

    static inline void init_switch_db()
    {
        sql::connection& db = get_sql_connection();
#ifdef USE_MYSQL
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
        CREATE TABLE IF NOT EXISTS switch_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        value INTEGER NOT NULL,
        updated_by TEXT,
        updated_at TEXT)
        )");
#endif
    }

    inline static void init_api_switch(Server& svr)
    {
        init_switch_db();
        add_route(svr, "/api/switch/v0/get", switch_get);
        add_route(svr, "/api/switch/v0/set", switch_set);
    }

}

#endif
