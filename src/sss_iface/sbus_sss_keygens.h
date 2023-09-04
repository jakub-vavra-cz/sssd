/*
    Generated by sbus code generator

    Copyright (C) 2017 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SBUS_SSS_KEYGENS_H_
#define _SBUS_SSS_KEYGENS_H_

#include <talloc.h>

#include "sbus/sbus_request.h"
#include "sss_iface/sbus_sss_arguments.h"

const char *
_sbus_sss_key_
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req);

const char *
_sbus_sss_key_s_0
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_s *args);

const char *
_sbus_sss_key_u_0
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_u *args);

const char *
_sbus_sss_key_ussu_0_1
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_ussu *args);

const char *
_sbus_sss_key_ussu_0_1_2
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_ussu *args);

const char *
_sbus_sss_key_usu_0_1
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_usu *args);

const char *
_sbus_sss_key_uusssu_0_1_2_3_4
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_uusssu *args);

const char *
_sbus_sss_key_uusu_0_1_2
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_uusu *args);

const char *
_sbus_sss_key_uuusu_0_1_2_3
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_uuusu *args);

#endif /* _SBUS_SSS_KEYGENS_H_ */
