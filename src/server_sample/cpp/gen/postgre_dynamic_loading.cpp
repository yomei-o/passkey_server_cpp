#include <libpq-fe.h>

#ifdef _WIN32			/* For Windows */
#include <windows.h>
#else
#include <dlfcn.h>
#endif /* WIN32 */

#ifdef _WIN32
#define DLLNAME_MYSQL "libpq.dll"
#else
#define DLLNAME_MYSQL "libpq.so"
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

void (*pf_PQfinish)(PGconn* conn)=NULL;
PGconn* (*pf_PQconnectdb)(const char* conninfo)=NULL;
ConnStatusType (*pf_PQstatus)(const PGconn* conn)=NULL;
char* (*pf_PQerrorMessage)(const PGconn* conn)=NULL;
PGresult* (*pf_PQexec)(PGconn* conn, const char* query)=NULL;
PGresult* (*pf_PQprepare)(PGconn* conn, const char* stmtName,const char* query, int nParams,const Oid* paramTypes)=NULL;

void (*pf_PQclear)(PGresult* res)=NULL;
PGresult* (*pf_PQexecPrepared)(PGconn* conn,const char* stmtName,int nParams,const char* const* paramValues,
	const int* paramLengths,const int* paramFormats,int resultFormat)=NULL;
char* (*pf_PQresultErrorMessage)(const PGresult* res)=NULL;
char* (*pf_PQresultErrorField)(const PGresult* res, int fieldcode)=NULL;
int	(*pf_PQntuples)(const PGresult* res) = NULL;
int	(*pf_PQnfields)(const PGresult* res)=NULL;

ExecStatusType (*pf_PQresultStatus)(const PGresult* res)=NULL;
char* (*pf_PQcmdTuples)(PGresult* res) = NULL;
char* (*pf_PQgetvalue)(const PGresult* res, int tup_num, int field_num) = NULL;
int	(*pf_PQgetlength)(const PGresult* res, int tup_num, int field_num) = NULL;
int	(*pf_PQgetisnull)(const PGresult* res, int tup_num, int field_num) = NULL;
size_t (*pf_PQescapeStringConn)(PGconn* conn,char* to, const char* from, size_t length,int* error) = NULL;

#ifdef __cplusplus
}
#endif

//

void PQfinish(PGconn* conn)
{
	if (pf_PQfinish == NULL)return;
	pf_PQfinish(conn);
}

PGconn* PQconnectdb(const char* conninfo)
{
	if (pf_PQconnectdb == NULL)return NULL;
	return pf_PQconnectdb(conninfo);
}
ConnStatusType PQstatus(const PGconn* conn)
{
	if (pf_PQstatus == NULL)return ConnStatusType::CONNECTION_BAD;
	return pf_PQstatus(conn);
}
char* PQerrorMessage(const PGconn* conn)
{
	if (pf_PQerrorMessage == NULL)return NULL;
	return pf_PQerrorMessage(conn);
}
PGresult* PQexec(PGconn* conn, const char* query)
{
	if (pf_PQexec == NULL)return NULL;
	return pf_PQexec(conn, query);
}
PGresult* PQprepare(PGconn* conn, const char* stmtName, const char* query, int nParams, const Oid* paramTypes)
{
	if (pf_PQprepare == NULL)return NULL;
	return pf_PQprepare(conn, stmtName, query, nParams, paramTypes);
}

void PQclear(PGresult* res)
{
	if (pf_PQclear == NULL)return;
	pf_PQclear(res);
}
PGresult* PQexecPrepared(PGconn* conn, const char* stmtName, int nParams, const char* const* paramValues,
	const int* paramLengths, const int* paramFormats, int resultFormat)
{
	if (pf_PQexecPrepared == NULL)return NULL;
	return pf_PQexecPrepared(conn, stmtName, nParams, paramValues, paramLengths, paramFormats, resultFormat);
}
char* PQresultErrorMessage(const PGresult* res)
{
	if (pf_PQresultErrorMessage == NULL)return NULL;
	return pf_PQresultErrorMessage(res);
}
char* PQresultErrorField(const PGresult* res, int fieldcode)
{
	if (pf_PQresultErrorField == NULL)return NULL;
	return pf_PQresultErrorField(res, fieldcode);
}
int	PQntuples(const PGresult* res)
{
	if (pf_PQntuples == NULL)return -1;
	return pf_PQntuples(res);
}
int	PQnfields(const PGresult* res)
{
	if (pf_PQnfields == NULL)return NULL;
	return pf_PQnfields(res);
}

ExecStatusType PQresultStatus(const PGresult* res)
{
	if (pf_PQresultStatus == NULL)return ExecStatusType::PGRES_FATAL_ERROR;
	return pf_PQresultStatus(res);
}
char* PQcmdTuples(PGresult* res)
{
	if (pf_PQcmdTuples == NULL)return NULL;
	return pf_PQcmdTuples(res);
}
char* PQgetvalue(const PGresult* res, int tup_num, int field_num)
{
	if (pf_PQgetvalue == NULL)return NULL;
	return pf_PQgetvalue(res, tup_num, field_num);
}

int	PQgetlength(const PGresult* res, int tup_num, int field_num)
{
	if (pf_PQgetlength == NULL)return -1;
	return pf_PQgetlength(res, tup_num, field_num);
}

int	PQgetisnull(const PGresult* res, int tup_num, int field_num)
{
	if (pf_PQgetisnull == NULL)return -1;
	return pf_PQgetisnull(res, tup_num, field_num);

}
size_t PQescapeStringConn(PGconn* conn, char* to, const char* from, size_t length, int* error)
{
	if (pf_PQescapeStringConn == NULL)return 0;
	return pf_PQescapeStringConn(conn, to, from, length, error);
}

//
static void* g_module;


class local_init
{
public:
	local_init(){
		g_module = dll_load(DLLNAME_MYSQL);
		if (g_module == NULL)return;
		pf_PQfinish = (void (*)(PGconn*))dll_access(g_module, "PQfinish");
		pf_PQconnectdb = (PGconn * (*)(const char*))dll_access(g_module, "PQconnectdb");
		pf_PQstatus = (ConnStatusType(*)(const PGconn*))dll_access(g_module, "PQstatus");
		pf_PQerrorMessage = (char* (*)(const PGconn * conn))dll_access(g_module, "PQerrorMessage");
		pf_PQexec = (PGresult* (*)(PGconn * conn, const char* query))dll_access(g_module, "PQexec");
		pf_PQprepare = (PGresult * (*)(PGconn * conn, const char* stmtName, const char* query, int nParams, const Oid * paramTypes))dll_access(g_module, "PQprepare");

		pf_PQclear = (void (*)(PGresult * res))dll_access(g_module, "PQclear");
		pf_PQexecPrepared = (PGresult * (*)(PGconn * conn, const char* stmtName, int nParams, const char* const* paramValues,
			const int* paramLengths, const int* paramFormats, int resultFormat))dll_access(g_module, "PQexecPrepared");
		pf_PQresultErrorMessage = (char* (*)(const PGresult * res))dll_access(g_module, "PQresultErrorMessage");
		pf_PQresultErrorField = (char* (*)(const PGresult * res, int fieldcode))dll_access(g_module, "PQresultErrorField");
		pf_PQntuples = (int	(*)(const PGresult * res))dll_access(g_module, "PQntuples");
		pf_PQnfields = (int	(*)(const PGresult * res))dll_access(g_module, "PQnfields");

		pf_PQresultStatus = (ExecStatusType (*)(const PGresult* res))dll_access(g_module, "PQresultStatus");
		pf_PQcmdTuples = (char* (*)(PGresult * res))dll_access(g_module, "PQcmdTuples");
		pf_PQgetvalue = (char* (*)(const PGresult * res, int tup_num, int field_num))dll_access(g_module, " PQgetvalue");
		pf_PQgetlength = (int	(*)(const PGresult * res, int tup_num, int field_num))dll_access(g_module, "PQgetlength");
		pf_PQgetisnull = (int	(*)(const PGresult * res, int tup_num, int field_num))dll_access(g_module, "PQgetisnull");
		pf_PQescapeStringConn = (size_t (*)(PGconn * conn, char* to, const char* from, size_t length, int* error))dll_access(g_module, "PQescapeStringConn");

		//pf_ = ()dll_access(g_module, "");
	}
	virtual ~local_init() {
		if (g_module == NULL)return;
		dll_close(g_module);
	}
};

static local_init s_init;



