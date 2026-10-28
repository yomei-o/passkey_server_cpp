#pragma once

/*
 * Copyright (c) 2014-2017, niXman (i dot nixman dog gmail dot com)
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

// clang-format off

#include <boost_preprocessor_config_config.hpp>

// enable the Clang support
#if defined(__clang__) && !BOOST_PP_VARIADICS
#undef BOOST_PP_VARIADICS
#define BOOST_PP_VARIADICS 1
#endif  // defined(__clang__)

// boost.preprocessor
#include <boost_preprocessor_cat.hpp>
#include <boost_preprocessor_facilities_expand.hpp>
#include <boost_preprocessor_punctuation_comma_if.hpp>
#include <boost_preprocessor_comparison_less.hpp>
#include <boost_preprocessor_arithmetic_add.hpp>
#include <boost_preprocessor_seq_for_each.hpp>
#include <boost_preprocessor_seq_for_each_i.hpp>
#include <boost_preprocessor_stringize.hpp>
#include <boost_preprocessor_tuple_elem.hpp>
#include <boost_preprocessor_tuple_size.hpp>
#include <boost_preprocessor_tuple_to_seq.hpp>

// tools
#include <sqlpp11_ppgen_tools_wrap_seq.h>
#include <sqlpp11_ppgen_tools_tuple_pop_front.h>

// table props
#include <sqlpp11_ppgen_tblops_engine.h>
#include <sqlpp11_ppgen_tblops_character_set.h>

// col props
#include <sqlpp11_ppgen_colops_auto_increment.h>
#include <sqlpp11_ppgen_colops_blob.h>
#include <sqlpp11_ppgen_colops_bool.h>
#include <sqlpp11_ppgen_colops_comment.h>
#include <sqlpp11_ppgen_colops_datetime.h>
#include <sqlpp11_ppgen_colops_default.h>
#include <sqlpp11_ppgen_colops_floating_point.h>
#include <sqlpp11_ppgen_colops_foreign_key.h>
#include <sqlpp11_ppgen_colops_index.h>
#include <sqlpp11_ppgen_colops_integer.h>
#include <sqlpp11_ppgen_colops_unsigned_integer.h>
#include <sqlpp11_ppgen_colops_not_null.h>
#include <sqlpp11_ppgen_colops_null.h>
#include <sqlpp11_ppgen_colops_primary_key.h>
#include <sqlpp11_ppgen_colops_text.h>
#include <sqlpp11_ppgen_colops_timestamp.h>
#include <sqlpp11_ppgen_colops_unique_index.h>
#include <sqlpp11_ppgen_colops_varchar.h>

/***************************************************************************/
// tools

#define SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table) \
  BOOST_PP_TUPLE_ELEM(0, BOOST_PP_EXPAND table)

#define SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(col) \
  BOOST_PP_TUPLE_ELEM(0, col)

#define SQLPP_DECLARE_TABLE_ENUM_COLUMNS(unused, table, elem) \
  ,table::SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem)

/***************************************************************************/
// columns

#define SQLPP_DECLARE_COLUMN_GEN_TRAITS_AUX(unused, size, idx, elem) \
  BOOST_PP_CAT(                                                      \
     SQLPP_DECLARE_COLUMN_GEN_TRAITS_                                \
    ,BOOST_PP_CAT(SQLPP_DECLARE_COLUMN_GET_TRAITS_LAZY_, elem)       \
  )(elem)                                                            \
  BOOST_PP_COMMA_IF(BOOST_PP_LESS(BOOST_PP_ADD(idx, 1), size))

#define SQLPP_DECLARE_COLUMN_GEN_TRAITS(props) \
  BOOST_PP_SEQ_FOR_EACH_I(                     \
     SQLPP_DECLARE_COLUMN_GEN_TRAITS_AUX       \
    ,BOOST_PP_TUPLE_SIZE(props)                \
    ,BOOST_PP_TUPLE_TO_SEQ(props)              \
  )

#define SQLPP_DECLARE_COLUMN(unused, data, elem)                             \
  struct SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem)                          \
  {                                                                          \
    struct _alias_t                                                          \
    {                                                                        \
      static constexpr const char _literal[] =                               \
        BOOST_PP_STRINGIZE(SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem));      \
      using _name_t = sqlpp::make_char_sequence<sizeof(_literal), _literal>; \
                                                                             \
      template <typename T>                                                  \
      struct _member_t                                                       \
      {                                                                      \
        T SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem);                        \
                                                                             \
        T& operator()()                                                      \
        {                                                                    \
          return SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem);                 \
        }                                                                    \
        const T& operator()() const                                          \
        {                                                                    \
          return SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem);                 \
        }                                                                    \
      }; /* struct _member_t */                                              \
    };   /* struct _alias_t */                                               \
                                                                             \
    using _traits = sqlpp::make_traits<                                      \
      SQLPP_DECLARE_COLUMN_GEN_TRAITS(SQLPP_BOOST_PP_TUPLE_POP_FRONT(elem))  \
    >;                                                                       \
  }; /* struct SQLPP_DECLARE_COLUMN_GET_COLUMN_NAME(elem) */

/***************************************************************************/
// table props

#define SQLPP_DECLARE_TABLE_GEN_PROPS_AUX(unused1, unused2, elem) \
  BOOST_PP_CAT(                                                   \
     SQLPP_DECLARE_TABLE_GEN_                                     \
    ,BOOST_PP_CAT(SQLPP_DECLARE_TABLE_GET_PROC_LAZY_, elem)       \
  )(elem)

#define SQLPP_DECLARE_TABLE_GEN_PROPS(table)                      \
  BOOST_PP_SEQ_FOR_EACH(                                          \
     SQLPP_DECLARE_TABLE_GEN_PROPS_AUX                            \
    ,~                                                            \
    ,BOOST_PP_TUPLE_TO_SEQ(SQLPP_BOOST_PP_TUPLE_POP_FRONT(table)) \
  )

/***************************************************************************/
// main

#define SQLPP_DECLARE_TABLE_IMPL(table, cols)                                    \
  namespace SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table)                            \
  {                                                                              \
    namespace BOOST_PP_CAT(SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table), _)         \
    {                                                                            \
      BOOST_PP_SEQ_FOR_EACH(                                                     \
         SQLPP_DECLARE_COLUMN                                                    \
        ,~                                                                       \
        ,cols                                                                    \
      )                                                                          \
    } /* namespace BOOST_PP_CAT(SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table), _) */ \
                                                                                 \
    struct SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table)                             \
      : sqlpp::table_t<                                                          \
        SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table)                                \
        BOOST_PP_SEQ_FOR_EACH(                                                   \
           SQLPP_DECLARE_TABLE_ENUM_COLUMNS                                      \
          ,BOOST_PP_CAT(SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table), _)            \
          ,cols                                                                  \
        )                                                                        \
      >                                                                          \
    {                                                                            \
      BOOST_PP_IF(                                                               \
         BOOST_PP_LESS(BOOST_PP_TUPLE_SIZE(table), 2)                            \
        ,BOOST_PP_TUPLE_EAT()                                                    \
        ,SQLPP_DECLARE_TABLE_GEN_PROPS                                           \
      )(BOOST_PP_EXPAND table)                                                   \
                                                                                 \
      struct _alias_t                                                            \
      {                                                                          \
        static constexpr const char _literal[] =                                 \
          BOOST_PP_STRINGIZE(SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table));         \
        using _name_t = sqlpp::make_char_sequence<sizeof(_literal), _literal>;   \
                                                                                 \
        template <typename T>                                                    \
        struct _member_t                                                         \
        {                                                                        \
          T SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table);                           \
                                                                                 \
          T& operator()()                                                        \
          {                                                                      \
            return SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table);                    \
          }                                                                      \
          const T& operator()() const                                            \
          {                                                                      \
            return SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table);                    \
          }                                                                      \
                                                                                 \
        }; /* struct _member_t */                                                \
      }; /* struct _alias_t */                                                   \
    }; /* struct SQLPP_DECLARE_TABLE_GET_TABLE_NAME(table) */                    \
  }

/***************************************************************************/

#define SQLPP_DECLARE_TABLE(table, cols)          \
  SQLPP_DECLARE_TABLE_IMPL(                       \
     BOOST_PP_CAT(SQLPP_WRAP_SEQUENCE_X table, 0) \
    ,BOOST_PP_CAT(SQLPP_WRAP_SEQUENCE_X cols, 0)  \
  )

/***************************************************************************/
