#ifndef DATABASE__H_
#define DATABASE__H_

//#define USE_MYSQL 1   // MySQL にするときは有効にする（接続先は環境変数 RDS_PROXY_HOST など）
#define USE_MYSQL_ENV 1

#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<ctime>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>

#include "json.hpp"

#ifdef USE_MYSQL
#include <sqlpp11_mysql_mysql.h>
#else
#include <sqlpp11_sqlite3_sqlite3.h>
#endif
#include <sqlpp11_sqlpp11.h>



using json = nlohmann::json;
#ifdef USE_MYSQL
namespace sql = sqlpp::mysql;
#else
namespace sql = sqlpp::sqlite3;
#endif



static inline std::string getenv_(const char* str)
{
        std::string ret;
        char* p;
        p=::getenv(str);
        if (p) {
            ret = p;
        }
        return ret;
}
static inline void db_global_init()
{
        static bool f_init = false;
        if (!f_init) {
            f_init = true;
#ifdef USE_MYSQL
            sql::global_library_init();
#endif
        }
}

static inline sql::connection_config& db_get_config()
{
        static sql::connection_config config;
        db_global_init();
#ifdef USE_MYSQL

#ifdef  USE_MYSQL_ENV
                config.host = getenv_("RDS_PROXY_HOST"); //"xxxx.rds.amazonaws.com";
        config.user = getenv_("USER_NAME"); //"xxxx";
        config.password = getenv_("PASSWORD"); // "xxxx";
        config.database = getenv_("DB_NAME"); // "xxxx";
        config.debug = false;

        if (config.host == "")config.host = "xxxx.rds.amazonaws.com";
        if(config.user=="")config.user = "xxxx";
        if(config.password=="")config.password = "xxxx";
        if(config.database=="")config.database = "xxxx";
#else

        config.user = "root";
        config.database = "sakila";
        config.debug = false;
        config.password = "xxxx";
#endif

#else
        config.path_to_database = "test_db.db";
        config.flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
        config.debug = true;
#endif
        return config;
}

static inline sql::connection& get_sql_connection()
{
    static sql::connection db_a(db_get_config());
    return db_a;
}

#endif

