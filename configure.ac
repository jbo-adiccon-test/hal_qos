##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2021 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AC_INIT(hal-qos, 1.0)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AC_LTDL_DLLIB
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AC_ENABLE_SHARED
AC_DISABLE_STATIC
