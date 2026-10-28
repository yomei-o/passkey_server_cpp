#pragma once
// -----------------------------------------------------------------------------
// httplib のバージョン差を吸収する互換シム。
//
// cpp-httplib 0.46 で multipart 送信用の型がリネームされた:
//     0.20.x 以前 : httplib::MultipartFormData      / httplib::MultipartFormDataItems
//     0.46 以降   : httplib::UploadFormData          / httplib::UploadFormDataItems
//
// アプリ側は常に新名 (UploadFormData / UploadFormDataItems) を使い、
// 古い版のときだけここで旧名へのエイリアスを補うことで、
// どちらの httplib でもビルドが通るようにする。
//
// 判定には CPPHTTPLIB_VERSION_NUM の有無を使う。
// このマクロは 0.20.1 には存在せず、0.46.1 には存在する。
// （本プロジェクトで切り替える 2 つの版を区別できればよい）
// -----------------------------------------------------------------------------
#include "httplib.h"

#ifndef CPPHTTPLIB_VERSION_NUM
namespace httplib {
using UploadFormData = MultipartFormData;
using UploadFormDataItems = MultipartFormDataItems;
} // namespace httplib
#endif
