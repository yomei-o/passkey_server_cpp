#pragma once

/*
 * Copyright (c) 2013-2015, Roland Bock
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sqlpp11_statement.h>

#include <sqlpp11_noop.h>
#include <sqlpp11_connection.h>
#include <sqlpp11_with.h>
#include <sqlpp11_select_flag_list.h>
#include <sqlpp11_select_column_list.h>
#include <sqlpp11_from.h>
#include <sqlpp11_where.h>
#include <sqlpp11_group_by.h>
#include <sqlpp11_having.h>
#include <sqlpp11_order_by.h>
#include <sqlpp11_limit.h>
#include <sqlpp11_for_update.h>
#include <sqlpp11_offset.h>
#include <sqlpp11_union.h>
#include <sqlpp11_expression.h>
#include <sqlpp11_wrong.h>

namespace sqlpp
{
  struct select_name_t
  {
  };

  struct select_t : public statement_name_t<select_name_t, tag::is_select>
  {
  };

  template <typename Context>
  Context& serialize(const select_name_t&, Context& context)
  {
    context << "SELECT ";

    return context;
  }

  template <typename Database>
  using blank_select_t = statement_t<Database,
                                     no_with_t,
                                     select_t,
                                     no_select_flag_list_t,
                                     no_select_column_list_t,
                                     no_from_t,
                                     no_where_t<true>,
                                     no_group_by_t,
                                     no_having_t,
                                     no_order_by_t,
                                     no_limit_t,
                                     no_offset_t,
                                     no_union_t,
                                     no_for_update_t>;

  inline blank_select_t<void> select()  // FIXME: These should be constexpr
  {
    return {};
  }

  template <typename... Columns>
  auto select(Columns... columns) -> decltype(blank_select_t<void>().columns(columns...))
  {
    return blank_select_t<void>().columns(columns...);
  }

  template <typename Database>
  blank_select_t<Database> dynamic_select(const Database& /*unused*/)
  {
    static_assert(std::is_base_of<connection, Database>::value, "Invalid database parameter");
    return {};
  }

  template <typename Database, typename... Columns>
  auto dynamic_select(const Database& /*unused*/, Columns... columns)
      -> decltype(blank_select_t<Database>().columns(columns...))
  {
    static_assert(std::is_base_of<connection, Database>::value, "Invalid database parameter");
    return blank_select_t<Database>().columns(columns...);
  }
}  // namespace sqlpp
