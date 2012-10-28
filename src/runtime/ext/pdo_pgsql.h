/*
   +----------------------------------------------------------------------+
   | HipHop for PHP                                                       |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010- Facebook, Inc. (http://www.facebook.com)         |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/

#ifndef __PDO_PGSQL_H__
#define __PDO_PGSQL_H__

#include <runtime/ext/pdo_driver.h>


namespace HPHP {
    enum {
	PDO_PGSQL_ATTR_DISABLE_NATIVE_PREPARED_STATEMENT = PDO_ATTR_DRIVER_SPECIFIC,
};

///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////

class PDOPgSql : public PDODriver {
public:
  PDOPgSql();

  virtual PDOConnection *createConnectionObject();
};

///////////////////////////////////////////////////////////////////////////////
}

#endif // __PDO_PGSQL_H__
