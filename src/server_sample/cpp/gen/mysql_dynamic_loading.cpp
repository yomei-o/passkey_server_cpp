#include <mysql.h>
//#include <stdio.h>

#ifdef _WIN32			/* For Windows */
#include <windows.h>
#else
#include <dlfcn.h>
#endif /* WIN32 */

#ifdef _WIN32
#define DLLNAME_MYSQL "libmysql.dll"
#else
#define DLLNAME_MYSQL "libmysqlclient.so"
#endif

static void* dll_load(const char* dllname)
{
	void* pFunclib = NULL;

	if (dllname == NULL) {
		return NULL;
	}
#ifdef _WIN32
	pFunclib = LoadLibraryA(dllname);
#else
	pFunclib = dlopen(dllname, RTLD_LAZY);
#endif
        //printf("pFunclib=%p (%s)\n",pFunclib,dllname);
	return pFunclib;
}

static void* dll_access(void* pDllmod, const char* funcname)
{
	void* pDll_func = NULL;

	if (pDllmod == NULL) {
		return NULL;
	}
	if (funcname == NULL) {
		return NULL;
	}
#ifdef _WIN32
	// FARPROC(関数ポインタ) から void* への変換は明示キャストが必要
	// (MSVC/Linux は通るが Windows + gcc ではエラーになる)
	pDll_func = reinterpret_cast<void*>(GetProcAddress((HMODULE)pDllmod, funcname));
#else
	pDll_func = dlsym(pDllmod, funcname);
#endif
	return pDll_func;
}

static void dll_close(void* pDllmod)
{
	if (pDllmod == NULL)return;
#ifdef _WIN32
	FreeLibrary((HMODULE)pDllmod);
#else
	dlclose(pDllmod);
#endif
	return;
}


//
#ifdef __cplusplus
extern "C"
{
#endif

MYSQL*  (STDCALL *pf_mysql_init)(MYSQL*)=NULL;
void (STDCALL *pf_mysql_close)(MYSQL*)=NULL;
int (STDCALL *pf_mysql_options)(MYSQL* , enum mysql_option,const void* )=NULL;
MYSQL* (STDCALL *pf_mysql_real_connect)(MYSQL* mysql, const char* host,
	const char* user, const char* passwd,
	const char* db, unsigned int port,
	const char* unix_socket,
	unsigned long clientflag)=NULL;
int (STDCALL *pf_mysql_server_init)(int, char** , char**)=NULL;
void (STDCALL *pf_mysql_server_end)()=NULL;
bool (STDCALL *pf_mysql_thread_init)(void)=NULL;
void (STDCALL* pf_mysql_thread_end)(void)=NULL;
int (STDCALL *pf_mysql_select_db)(MYSQL*, const char*)=NULL;
int (STDCALL *pf_mysql_query)(MYSQL*, const char*)=NULL;
uint64_t (STDCALL *pf_mysql_affected_rows)(MYSQL* mysql)=NULL;
uint64_t (STDCALL* pf_mysql_insert_id)(MYSQL* mysql) = NULL;
const char* (STDCALL* pf_mysql_error)(MYSQL* mysql) = NULL;
int (STDCALL* pf_mysql_set_character_set)(MYSQL* mysql, const char* csname)=NULL;
MYSQL_RES* (STDCALL* pf_mysql_store_result)(MYSQL* mysql)=NULL;
void (STDCALL* pf_mysql_free_result)(MYSQL_RES* result)=NULL;
MYSQL_ROW (STDCALL* pf_mysql_fetch_row)(MYSQL_RES* result)=NULL;
unsigned long* (STDCALL* pf_mysql_fetch_lengths)(MYSQL_RES* result)=NULL;
unsigned long (STDCALL* pf_mysql_real_escape_string)(MYSQL* mysql, char* to,const char* from,unsigned long length)=NULL;
unsigned int (STDCALL * pf_mysql_thread_safe)(void)=NULL;

MYSQL_STMT* (STDCALL* pf_mysql_stmt_init)(MYSQL* mysql)=NULL;
int (STDCALL* pf_mysql_stmt_prepare)(MYSQL_STMT* stmt, const char* query,unsigned long length)=NULL;
int (STDCALL* pf_mysql_stmt_execute)(MYSQL_STMT* stmt)=NULL;
int (STDCALL* pf_mysql_stmt_fetch)(MYSQL_STMT* stmt)=NULL;
int (STDCALL* pf_mysql_stmt_fetch_column)(MYSQL_STMT* stmt, MYSQL_BIND* bind_arg,unsigned int column, unsigned long offset)=NULL;

bool (STDCALL* pf_mysql_stmt_bind_param)(MYSQL_STMT* stmt, MYSQL_BIND* bnd)=NULL;
bool (STDCALL* pf_mysql_stmt_bind_result)(MYSQL_STMT* stmt, MYSQL_BIND* bnd) = NULL;
bool (STDCALL* pf_mysql_stmt_close)(MYSQL_STMT* stmt) = NULL;
bool (STDCALL* pf_mysql_stmt_free_result)(MYSQL_STMT* stmt) = NULL;

unsigned int (STDCALL* pf_mysql_stmt_errno)(MYSQL_STMT* stmt)=NULL;
const char* (STDCALL* pf_mysql_stmt_error)(MYSQL_STMT* stmt)=NULL;
uint64_t(STDCALL* pf_mysql_stmt_insert_id)(MYSQL_STMT* stmt) = NULL;

#ifdef __cplusplus
}
#endif

//

MYSQL* STDCALL mysql_init(MYSQL* m)
{
	if (pf_mysql_init == NULL)return NULL;
	return pf_mysql_init(m);
}

void STDCALL mysql_close(MYSQL* m) 
{
	if(pf_mysql_close == NULL)return;
	pf_mysql_close(m);
}

int STDCALL mysql_options(MYSQL* mysql, enum mysql_option option,
	const void* arg)
{
	if (pf_mysql_options == NULL)return -1;
	return pf_mysql_options(mysql, option, arg);
}

MYSQL* STDCALL mysql_real_connect(MYSQL* mysql, const char* host,
	const char* user, const char* passwd,
	const char* db, unsigned int port,
	const char* unix_socket,
	unsigned long clientflag) {
	if (pf_mysql_real_connect == NULL)return NULL;
	return pf_mysql_real_connect(mysql, host, user,passwd,db, port, unix_socket, clientflag);
}

int STDCALL mysql_server_init(int argc, char** argv, char** groups)
{
	if (pf_mysql_server_init== NULL)return -1;
	return pf_mysql_server_init(argc, argv, groups);
}
void STDCALL mysql_server_end(void)
{
	if (pf_mysql_server_end == NULL)return;
	pf_mysql_server_end();
}
bool STDCALL mysql_thread_init(void)
{
	if (pf_mysql_thread_init == NULL)return false;
	return pf_mysql_thread_init();

}
void STDCALL mysql_thread_end(void)
{
	if (pf_mysql_thread_end == NULL)return;
	pf_mysql_thread_end();
}

int STDCALL mysql_select_db(MYSQL* mysql, const char* db)
{
	if (pf_mysql_select_db == NULL)return -1;
	return pf_mysql_select_db(mysql,db);

}
int STDCALL mysql_query(MYSQL* mysql, const char* q)
{
	if (pf_mysql_query == NULL)return -1;
	return pf_mysql_query(mysql, q);
}

uint64_t STDCALL mysql_affected_rows(MYSQL* mysql)
{
	if (pf_mysql_affected_rows == NULL)return -1;
	return pf_mysql_affected_rows(mysql);
}
uint64_t STDCALL mysql_insert_id(MYSQL* mysql)
{
	if (pf_mysql_insert_id == NULL)return -1;
	return pf_mysql_insert_id(mysql);
}
const char* STDCALL mysql_error(MYSQL* mysql)
{
	if (pf_mysql_error == NULL)return NULL;
	return pf_mysql_error(mysql);
}

int STDCALL mysql_set_character_set(MYSQL* mysql, const char* csname)
{
	if (pf_mysql_set_character_set == NULL)return -1;
	return pf_mysql_set_character_set(mysql, csname);
}
MYSQL_RES* STDCALL mysql_store_result(MYSQL* mysql)
{
	if (pf_mysql_store_result == NULL)return NULL;
	return pf_mysql_store_result(mysql);
}
void STDCALL mysql_free_result(MYSQL_RES* result)
{
	if (pf_mysql_free_result == NULL)return;
	pf_mysql_free_result(result);
}
MYSQL_ROW STDCALL mysql_fetch_row(MYSQL_RES* result)
{
	if (pf_mysql_fetch_row == NULL)return 0;
	return pf_mysql_fetch_row(result);
}
unsigned long* STDCALL mysql_fetch_lengths(MYSQL_RES* result)
{
	if (pf_mysql_fetch_lengths == NULL)return 0;
	return pf_mysql_fetch_lengths(result);
}
unsigned long STDCALL mysql_real_escape_string(MYSQL* mysql, char* to, const char* from, unsigned long length)
{
	if (pf_mysql_real_escape_string==NULL)return 0;
	return pf_mysql_real_escape_string(mysql, to, from, length);
}
unsigned int STDCALL mysql_thread_safe(void)
{
	if (pf_mysql_thread_safe == NULL)return 0;
	return pf_mysql_thread_safe();
}

MYSQL_STMT* STDCALL mysql_stmt_init(MYSQL* mysql)
{
	if (pf_mysql_stmt_init == NULL)return NULL;
	return pf_mysql_stmt_init(mysql);
}
int STDCALL mysql_stmt_prepare(MYSQL_STMT* stmt, const char* query,unsigned long length)
{
	if (pf_mysql_stmt_prepare == NULL)return -1;
	return pf_mysql_stmt_prepare(stmt, query,length);
}
int STDCALL mysql_stmt_execute(MYSQL_STMT* stmt)
{
	if (pf_mysql_stmt_execute == NULL)return -1;
	return pf_mysql_stmt_execute(stmt);
}
int STDCALL mysql_stmt_fetch(MYSQL_STMT* stmt)
{
	if (pf_mysql_stmt_fetch == NULL)return -1;
	return pf_mysql_stmt_fetch(stmt);
}
int STDCALL mysql_stmt_fetch_column(MYSQL_STMT* stmt, MYSQL_BIND* bind_arg,unsigned int column, unsigned long offset)
{
	if (pf_mysql_stmt_fetch_column == NULL)return -1;
	return pf_mysql_stmt_fetch_column(stmt, bind_arg, column, offset);
}

bool STDCALL mysql_stmt_bind_param(MYSQL_STMT* stmt, MYSQL_BIND* bnd) 
{
	if (pf_mysql_stmt_bind_param == NULL)return false;
	return pf_mysql_stmt_bind_param(stmt, bnd);
}
bool STDCALL mysql_stmt_bind_result(MYSQL_STMT* stmt, MYSQL_BIND* bnd)
{
	if (pf_mysql_stmt_bind_result == NULL)return false;
	return pf_mysql_stmt_bind_result(stmt, bnd);

}
bool STDCALL mysql_stmt_close(MYSQL_STMT* stmt)
{
	if (pf_mysql_stmt_close == NULL)return false;
	return pf_mysql_stmt_close(stmt);

}
bool STDCALL mysql_stmt_free_result(MYSQL_STMT* stmt)
{
	if (pf_mysql_stmt_free_result == NULL)return false;
	return pf_mysql_stmt_free_result(stmt);
}

unsigned int STDCALL mysql_stmt_errno(MYSQL_STMT* stmt) 
{
	if (pf_mysql_stmt_errno == NULL)return 0;
	return pf_mysql_stmt_errno(stmt);
}
const char* STDCALL mysql_stmt_error(MYSQL_STMT* stmt)
{
	if (pf_mysql_stmt_error == NULL)return NULL;
	return pf_mysql_stmt_error(stmt);
}
uint64_t STDCALL mysql_stmt_insert_id(MYSQL_STMT* stmt)
{
	if (pf_mysql_stmt_insert_id == NULL)return 0;
	return pf_mysql_stmt_insert_id(stmt);
}

//
static void* g_module;


class local_init
{
public:
	local_init(){
		g_module = dll_load(DLLNAME_MYSQL);
		if (g_module == NULL)return;
		pf_mysql_init = (MYSQL * (STDCALL *)(MYSQL*))dll_access(g_module, "mysql_init");
		pf_mysql_close = (void (STDCALL *)(MYSQL*))dll_access(g_module, "mysql_close");
		pf_mysql_options = (int (STDCALL *)(MYSQL*, enum mysql_option, const void*))dll_access(g_module, "mysql_options");
		pf_mysql_real_connect = (MYSQL * (STDCALL *)(MYSQL*,const char*,const char*,const char*,
			const char*,unsigned int,const char*,unsigned long))dll_access(g_module, "mysql_real_connect");
		pf_mysql_server_init = (int (STDCALL *)(int, char**, char**))dll_access(g_module, "mysql_server_init");
		pf_mysql_server_end = (void (STDCALL *)())dll_access(g_module, "mysql_server_end");
		pf_mysql_thread_init = (bool (STDCALL *)(void))dll_access(g_module, "mysql_thread_init");
		pf_mysql_thread_end = (void (STDCALL *)(void))dll_access(g_module, "mysql_thread_end");
		pf_mysql_select_db = (int (STDCALL *)(MYSQL*, const char*))dll_access(g_module, "mysql_select_db");
		pf_mysql_query = (int (STDCALL*)(MYSQL*, const char*))dll_access(g_module, "mysql_query");
		pf_mysql_affected_rows = (uint64_t (STDCALL*)(MYSQL*))dll_access(g_module, "mysql_affected_rows");
		pf_mysql_insert_id = (uint64_t (STDCALL*)(MYSQL*))dll_access(g_module, "mysql_insert_id");
		pf_mysql_error = (const char* (STDCALL*)(MYSQL*))dll_access(g_module, "mysql_error");
		pf_mysql_set_character_set = (int (STDCALL*)(MYSQL*, const char*))dll_access(g_module, "mysql_set_character_set");
		pf_mysql_store_result = (MYSQL_RES* (STDCALL *)(MYSQL*))dll_access(g_module, "mysql_store_result");
		pf_mysql_free_result = (void (STDCALL *)(MYSQL_RES*))dll_access(g_module, "mysql_free_result");
		pf_mysql_fetch_row = (MYSQL_ROW (STDCALL *)(MYSQL_RES*))dll_access(g_module, "mysql_fetch_row");
		pf_mysql_fetch_lengths = (unsigned long* (STDCALL *)(MYSQL_RES*))dll_access(g_module, "mysql_fetch_lengths");
		pf_mysql_real_escape_string = (unsigned long (STDCALL *)(MYSQL*, char*, const char*, unsigned long))dll_access(g_module, "mysql_real_escape_string");
		pf_mysql_thread_safe = (unsigned int (STDCALL *)(void))dll_access(g_module, "mysql_thread_safe");

		pf_mysql_stmt_init = (MYSQL_STMT* (STDCALL *)(MYSQL *))dll_access(g_module, "mysql_stmt_init");
		pf_mysql_stmt_prepare = (int (STDCALL *)(MYSQL_STMT * stmt, const char* query, unsigned long length))dll_access(g_module, "mysql_stmt_prepare");
		pf_mysql_stmt_execute = (int (STDCALL *)(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_execute");
		pf_mysql_stmt_fetch = (int (STDCALL *)(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_fetch");
		pf_mysql_stmt_fetch_column = (int (STDCALL *)(MYSQL_STMT * stmt, MYSQL_BIND * bind_arg, unsigned int column, unsigned long offset))dll_access(g_module, "mysql_stmt_fetch_column");

		pf_mysql_stmt_bind_param = (bool (STDCALL *)(MYSQL_STMT * stmt, MYSQL_BIND * bnd))dll_access(g_module, "mysql_stmt_bind_param");
		pf_mysql_stmt_bind_result = (bool (STDCALL *)(MYSQL_STMT * stmt, MYSQL_BIND * bnd))dll_access(g_module, "mysql_stmt_bind_result");
		pf_mysql_stmt_close = (bool (STDCALL*)(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_close");
		pf_mysql_stmt_free_result = (bool (STDCALL *)(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_free_result");

		pf_mysql_stmt_errno = (unsigned int (STDCALL* )(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_errno");
		pf_mysql_stmt_error = (const char* (STDCALL *)(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_error");
		pf_mysql_stmt_insert_id = (uint64_t (STDCALL* )(MYSQL_STMT * stmt))dll_access(g_module, "mysql_stmt_insert_id");

		//pf_ = ()dll_access(g_module, "");
	}
	virtual ~local_init() {
		if (g_module == NULL)return;
		dll_close(g_module);
	}
};

static local_init s_init;



