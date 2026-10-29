
#define ENABLE_API_PASSKEY 1
#define ENABLE_API_TENANT 1


#include "lambda_server.h"

#ifdef ENABLE_API_PASSKEY
#include "testsv_api_passkey.h"
#endif

#ifdef ENABLE_API_TENANT
#include "testsv_api_tenant.h"
#endif


int main()
{
	Server svr;
	int port = 8080;
	char* p;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

	if (!svr.is_valid()) {
		printf("server has an error...\n");
		return -1;
	}
	// file
	svr.set_mount_point("/html", "html");

	// ポートは環境変数 POST（PORT ではない）
	if ((p = getenv("POST"))) {
		port = std::atoi(p);
	}

#ifdef ENABLE_API_PASSKEY
	passkey::init_api_passkey(svr);
#endif

#ifdef ENABLE_API_TENANT
	tenant_api::init_api_tenant(svr);
#endif

	fprintf(stderr,"http server started port=%d\n",port);
	svr.listen("0.0.0.0", port);

	return 0;
}
