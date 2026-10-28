#ifndef LAMBDA_SERVER_H
#define LAMBDA_SERVER_H

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "httplib.h"
#include "json.hpp"


using json = nlohmann::json;
using namespace httplib;

#define API_CALL(func) \
		std::string auth = get_auth(req); \
        json o_req = get_request(req); \
        json o_res;\
		try{o_res = func(o_req,auth); }catch(...){}\
        std::string str_res = get_response(o_res); \
        res.set_content(str_res, "application/json"); \
		common_response(req, res)

#define API_CALL_REQ(func) \
		std::string auth = get_auth(req); \
        json o_req = get_request(req); \
        json o_res;\
		try{o_res = func(o_req,auth,req); }catch(...){}\
        std::string str_res = get_response(o_res); \
        res.set_content(str_res, "application/json"); \
		common_response(req, res)

inline static std::string dump_headers(const Headers& headers) {
	std::string s;
	char buf[BUFSIZ];

	for (auto it = headers.begin(); it != headers.end(); ++it) {
		const auto& x = *it;
		snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
		s += buf;
	}

	return s;
}

inline static void common_response(const Request& req, Response& res) {
	res.set_header("Access-Control-Allow-Origin", "*");
	res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
	res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
}


inline static std::string trim(std::string src, std::string tr=" ", uint8_t flag = 3)
{
	size_t start_pos, end_pos;
	start_pos = ((flag == 1 || flag == 3) ? src.find_first_not_of(tr) : 0);
	end_pos = ((flag == 2 || flag == 3) ? src.find_last_not_of(tr) : src.size());
	if (start_pos == -1 || end_pos == -1)return "";
	return src.substr(start_pos, end_pos - start_pos + 1);
}

inline static std::string get_auth(const Request& req)
{
	std::string ret = "error";
	try {
		if (!req.has_header("Authorization"))return ret;

		std::string val = req.get_header_value("Authorization");
		int idx = val.find("Bearer");
		if (idx == -1)return ret;

		std::string tmp = val.substr(idx + 6);
		tmp = trim(tmp);
		ret = tmp;
	}
	catch (...) {}
	return ret;
}

inline static json get_request(const Request& req)
{
	json ret;
	if (req.method == "GET")return ret;
    try {
        ret = json::parse(req.body);
    }
    catch (...) {}
	return ret;
}

inline static std::string get_response(json & res)
{
	std::string ret;
    try {
        ret = res.dump(4);
    }
    catch (...) {}
	return ret;
}


#endif


