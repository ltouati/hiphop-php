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

#include <runtime/ext/pdo_pgsql.h>
#include <runtime/ext/ext_stream.h>
#include <util/logger.h>
#include <libpq-fe.h>
#include <runtime/base/array/zend_array.h>

#define PHP_PDO_PGSQL_CONNECTION_FAILURE_SQLSTATE "08006"
#define pdo_pgsql_sqlstate(r) PQresultErrorField(r, PG_DIAG_SQLSTATE)

namespace HPHP
{
class PDOPgSqlConnection;

class PDOPgColumn : public PDOColumn
{
public:
    PDOPgColumn();
    ~PDOPgColumn();

public:
    int pgsql_type;
};

class PDOPgSqlStatement : public PDOStatement
{
public:
    PDOPgSqlStatement(PDOPgSqlConnection *conn, PGconn *server);
    virtual ~PDOPgSqlStatement();

    bool create(CStrRef sql, CArrRef options);

    virtual bool support(SupportedMethod method);
    virtual bool executer();
    virtual bool fetcher(PDOFetchOrientation ori, long offset);
    virtual bool describer(int colno);
    virtual bool getColumn(int colno, Variant &value);
    virtual bool paramHook(PDOBoundParam *param, PDOParamEvent event_type);
    virtual bool getColumnMeta(int64 colno, Array &return_value);
    virtual bool nextRowset();
    virtual bool cursorCloser();

private:
    PDOPgSqlConnection *m_conn;
    PGconn              *m_server;
    std::string         *stmt_name;
    const char          **param_values;
    int                 *param_lengths;
    int                 *param_formats;
    Oid                 *param_types;
    PGresult            *result;
    int                 current_row;
    std::string         *cursor_name;
    bool                is_prepared;
    std::string          query;
    bool                executed;
};

///////////////////////////////////////////////////////////////////////////////



class PDOPgSqlConnection : public PDOConnection
{
public:
    PDOPgSqlConnection();
    virtual ~PDOPgSqlConnection();
    virtual bool create(CArrRef options);
    int handleError(const char *codeString,int codeInt,const char *file, int line);
    virtual bool preparer(CStrRef sql, sp_PDOStatement *stmt,
                          CVarRef options);

    virtual int64 doer(CStrRef sql);
    PGconn *m_server;
    string nextStatement();
    int			m_statements;
};


PDOPgColumn::PDOPgColumn() :
    pgsql_type(-1)
{

}
PDOPgColumn::~PDOPgColumn()
{
}


PDOPgSqlStatement::PDOPgSqlStatement(PDOPgSqlConnection *conn, PGconn *server) :
    m_conn(conn),
    m_server(server),
    stmt_name(NULL),
    param_values(NULL),
    param_lengths(NULL),
    param_formats(NULL),
    param_types(NULL),
    result(NULL),
    current_row(-1),
    cursor_name(NULL),
    is_prepared(false),
    executed(false)

{
}
PDOPgSqlStatement::~PDOPgSqlStatement()
{

    if (this->result)
    {
        /* free the resource */
        PQclear(this->result);
        this->result = NULL;
    }

    if (this->stmt_name)
    {
        PGresult *res;

        if (this->is_prepared)
        {
            std::string tmp;
            Util::string_printf(tmp, "DEALLOCATE %s", this->stmt_name->c_str());
            res = PQexec(this->m_server, tmp.c_str());
            if (res)
            {
                PQclear(res);
            }
        }
        delete this->stmt_name;
        this->stmt_name = NULL;
    }
    if (this->param_lengths)
    {
        free(this->param_lengths);
        this->param_lengths = NULL;
    }
    if (this->param_values)
    {
        free(this->param_values);
        this->param_values = NULL;
    }
    if (this->param_formats)
    {
        free(this->param_formats);
        this->param_formats = NULL;
    }
    if (this->param_types)
    {
        free(this->param_types);
        this->param_types = NULL;
    }


    if (this->cursor_name)
    {
        PGresult *res;

        std::string tmp;
        Util::string_printf(tmp, "CLOSE %s", this->cursor_name->c_str());
        res = PQexec(this->m_server, tmp.c_str());
        if (res)
        {
            PQclear(res);
        }
        delete this->cursor_name;
        this->cursor_name = NULL;
    }

}

static long pdo_attr_lval(CArrRef options, int opt, long defaultValue)
{
    if (options.exists(opt))
    {
        return options[opt].toInt64();
    }
    return defaultValue;
}
bool PDOPgSqlStatement::create(CStrRef sql, CArrRef driver_options)
{
    int scrollable;
    String nsql;
    int emulate = 0;


    this->query = sql;
    scrollable = pdo_attr_lval(driver_options, PDO_ATTR_CURSOR,
                               PDO_CURSOR_FWDONLY) == PDO_CURSOR_SCROLL;

    if (scrollable)
    {
        if (this->cursor_name)
        {
            delete(this->cursor_name);
            this->cursor_name = NULL;
        }
        std::string tmp;
        Util::string_printf(tmp,"pdo_crsr_%08x",++this->m_conn->m_statements);
        this->cursor_name = new std::string(tmp);
        emulate = 1;
    }

    else if (driver_options.size()>0)
    {
        if (pdo_attr_lval(driver_options, PDO_ATTR_DRIVER_SPECIFIC, 0) == 1 ||
                pdo_attr_lval(driver_options, PDO_ATTR_EMULATE_PREPARES, 0) == 1)
        {
            emulate = 1;
        }
    }
    else
    {
        emulate = 0;
    }

    if (!emulate && PQprotocolVersion(this->m_server) > 2)
    {
        supports_placeholders = PDO_PLACEHOLDER_NAMED;
        this->named_rewrite_template = "$%d";
        String nsql;
        int ret = pdo_parse_params(this, sql, nsql);
        if (ret == 1)
        {
            /* query was rewritten */
        }
        else if (ret == -1)
        {
            /* failed to parse */
            return false;
        }
        else
        {
            nsql = sql;
        }
        /**

               const char *source = sql.c_str();
               StringBuffer nsql;
               int numberOfParameters = 0;
               for(int i=0; i<sql.length(); i++)
               {
                   if(source[i]=='?')
                   {
                       nsql.printf("$%d",(numberOfParameters+1));
                       numberOfParameters++;
                   }
                   else
                   {
                       nsql.append(source[i]);
                   }
               }
               **/
        std::string tmp = "";
        Util::string_printf(tmp,"pdo_stmt_%08x",++this->m_conn->m_statements);
        this->stmt_name = new std::string(tmp);
        this->query = nsql;

        return true;
    }

    this->supports_placeholders = PDO_PLACEHOLDER_NONE;
    return true;
}
///////////////////////////////////////////////////////////////////////////////
bool PDOPgSqlStatement::support(SupportedMethod method)
{
    switch (method)
    {
    case MethodSetAttribute:
    case MethodGetAttribute:
        return false;
    default:
        break;
    }
    return true;
}

bool PDOPgSqlConnection::preparer(CStrRef sql, sp_PDOStatement *stmt,
                                  CVarRef options)
{
    m_statements++;
    PDOPgSqlStatement *s = new PDOPgSqlStatement(this, m_server);
    *stmt = s;
    if (s->create(sql, options))
    {
        alloc_own_columns = 1;
        return true;
    }


    stmt->reset();
    strcpy(error_code, this->error_code);
    return false;
}

string PDOPgSqlConnection::nextStatement()
{
    string ret;
    Util::string_printf(ret, "pdo_smt%d",m_statements);
    return ret;
}

int64 PDOPgSqlConnection::doer(CStrRef sql)
{
    PGresult* result = PQexec(m_server, sql.c_str());

    if (0 == result)
    {
        handleError(pdo_pgsql_sqlstate(result),PQresultStatus(result),__FILE__,__LINE__);
    }

    ExecStatusType const status = PQresultStatus(result);
    if (PGRES_COMMAND_OK != status && PGRES_TUPLES_OK!=status)
    {
        PQclear(result);
        handleError(pdo_pgsql_sqlstate(result),PQresultStatus(result),__FILE__,__LINE__);
        return -1;
    }

    PQclear(result);

    return 1;
}


PDOPgSqlConnection::PDOPgSqlConnection() : m_server(NULL),m_statements(0)
{
}
PDOPgSqlConnection::~PDOPgSqlConnection()
{
    if(m_server)
    {
        PQfinish(m_server);
        m_server = NULL;
    }
}

bool PDOPgSqlStatement::executer()
{
    ExecStatusType status;

    /* ensure that we free any previous unfetched results */
    if(this->result)
    {
        PQclear(this->result);
        this->result = NULL;
    }

    this->current_row = 0;

    if (this->cursor_name!=NULL && this->cursor_name->length()>0)
    {
        char *q = NULL;

        if (this->is_prepared)
        {
            std::string tmp;
            Util::string_printf(tmp,"CLOSE %s", this->cursor_name->c_str());
            this->result = PQexec(this->m_server, tmp.c_str());
        }

        std::string tmp;
        Util::string_printf(tmp,"DECLARE %s SCROLL CURSOR WITH HOLD FOR %s", this->cursor_name->c_str(), this->active_query_string.c_str());
        this->result = PQexec(this->m_server, tmp.c_str());

        /* check if declare failed */
        status = PQresultStatus(this->result);
        if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
        {
            this->m_conn->handleError(pdo_pgsql_sqlstate(this->result),status,__FILE__,__LINE__);
            return false;
        }

        /* the cursor was declared correctly */
        this->is_prepared = true;

        /* fetch to be able to get the number of tuples later, but don't advance the cursor pointer */
        Util::string_printf(tmp,"FETCH FORWARD 0 FROM %s", this->cursor_name->c_str());
        this->result = PQexec(this->m_server, q);
    }
    else if (this->stmt_name!=NULL)
    {
        /* using a prepared statement */
        if (!this->is_prepared)
        {
stmt_retry:


            /* we deferred the prepare until now, because we didn't
             * know anything about the parameter types; now we do */
            this->result = PQprepare(this->m_server, this->stmt_name->c_str(), this->query.c_str(),
                                     this->bound_params.size(),
                                     this->param_types);
            status = PQresultStatus(this->result);
            switch (status)
            {
            case PGRES_COMMAND_OK:
            case PGRES_TUPLES_OK:
                /* it worked */
                this->is_prepared = 1;
                PQclear(this->result);
                break;
            default:
            {
                char *sqlstate = pdo_pgsql_sqlstate(this->result);
                /* 42P05 means that the prepared statement already existed. this can happen if you use
                 * a connection pooling software line pgpool which doesn't close the db-connection once
                 * php disconnects. if php dies (no chance to run RSHUTDOWN) during execution it has no
                 * chance to DEALLOCATE the prepared statements it has created. so, if we hit a 42P05 we
                 * deallocate it and retry ONCE (thies 2005.12.15)
                 */
                if (sqlstate && !strcmp(sqlstate, "42P05"))
                {
                    char buf[100]; /* stmt_name == "pdo_crsr_%08x" */
                    PGresult *res;
                    snprintf(buf, sizeof(buf), "DEALLOCATE %s", this->stmt_name->c_str());
                    res = PQexec(this->m_server, buf);
                    if (res)
                    {
                        PQclear(res);
                    }
                    goto stmt_retry;
                }
                else
                {
                    this->m_conn->handleError(sqlstate,status,__FILE__,__LINE__);

                    return false;
                }
            }
            }
        }
        this->result = PQexecPrepared(this->m_server, this->stmt_name->c_str(),
                                      this->bound_params.size(),
                                      (const char**)this->param_values,
                                      this->param_lengths,
                                      this->param_formats,
                                      0);
    }
    else
    {

        this->result = PQexec(this->m_server, this->active_query_string);
    }
    status = PQresultStatus(this->result);

    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
    {
        this->m_conn->handleError(pdo_pgsql_sqlstate(this->result),status,__FILE__,__LINE__);
        return false;
    }

    if (!this->executed && !this->column_count)
    {
        this->column_count = (int) PQnfields(this->result);
        //cols = malloc(this->column_count, sizeof(pdo_pgsql_column));
    }

    if (status == PGRES_COMMAND_OK)
    {
        this->row_count = (long)atoi(PQcmdTuples(this->result));
        //H->pgoid = PQoidValue(this->result);
    }
    else
    {
        this->row_count = (long)PQntuples(this->result);
    }
    return true;
}

bool PDOPgSqlStatement::fetcher(PDOFetchOrientation ori, long offset)
{
    if (this->cursor_name)
    {
        StringBuffer ori_str;
        StringBuffer query;
        ExecStatusType status;

        switch (ori)
        {
        case PDO_FETCH_ORI_NEXT:
            ori_str.append("NEXT");
            break;
        case PDO_FETCH_ORI_PRIOR:
            ori_str.append("BACKWARD");
            break;
        case PDO_FETCH_ORI_FIRST:
            ori_str.append("FIRST");
            break;
        case PDO_FETCH_ORI_LAST:
            ori_str.append("LAST");
            break;
        case PDO_FETCH_ORI_ABS:
            ori_str.printf("ABSOLUTE %ld", offset);
            break;
        case PDO_FETCH_ORI_REL:
            ori_str.printf("RELATIVE %ld", offset);
            break;
        default:
            return false;
        }
        query.printf("FETCH %s FROM %s", ori_str.detach().c_str(), this->cursor_name->c_str());
        this->result = PQexec(this->m_server, query.detach().c_str());
        status = PQresultStatus(this->result);

        if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
        {
            this->m_conn->handleError(pdo_pgsql_sqlstate(this->result),status,__FILE__,__LINE__);

            return false;
        }

        if (PQntuples(this->result))
        {
            this->current_row = 1;
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        if (this->current_row < this->row_count)
        {
            this->current_row++;
            return true;
        }
        else
        {
            return false;
        }
    }
}

#define BOOLOID     16
#define BYTEAOID    17
#define INT8OID     20
#define INT2OID     21
#define INT4OID     23
#define TEXTOID     25
#define OIDOID      26


bool PDOPgSqlStatement::describer(int colno)
{
    Array cols = this->columns;

    if (!this->result)
    {
        return 0;
    }
    if (columns.empty())
    {
        for (int i = 0; i < column_count; i++)
        {
            columns.set(i, Object(new PDOPgColumn()));
        }
    }
    PDOPgColumn *column = columns[colno].toObject().getTyped<PDOPgColumn>();

    column->name = String(PQfname(this->result, colno));
    column->maxlen = PQfsize(this->result, colno);
    column->precision = PQfmod(this->result, colno);
    column->pgsql_type = PQftype(this->result, colno);

    switch(column->pgsql_type)
    {

    case BOOLOID:
        column->param_type = PDO_PARAM_BOOL;
        break;

    case OIDOID:
        /* did the user bind the column as a LOB ? */
        if (this->bound_columns.size()>0 && (
                    this->bound_columns.exists(colno)||
                    this->bound_columns.exists(column->name)))
        {
            PDOBoundParam *param = NULL;
            if(this->bound_columns.exists(colno))
            {
                param = this->bound_columns[colno].toObject().getTyped<PDOBoundParam>();
            }
            else
            {
                param = this->bound_columns[column->name].toObject().getTyped<PDOBoundParam>();

            }
            if (PDO_PARAM_TYPE(param->param_type) == PDO_PARAM_LOB)
            {
                column->param_type = PDO_PARAM_LOB;
                break;
            }
        }
        column->param_type = PDO_PARAM_INT;
        break;

    case INT2OID:
    case INT4OID:
        column->param_type = PDO_PARAM_INT;
        break;

    case INT8OID:
        if (sizeof(long)>=8)
        {
            column->param_type = PDO_PARAM_INT;
        }
        else
        {
            column->param_type = PDO_PARAM_STR;
        }
        break;

    case BYTEAOID:
        column->param_type = PDO_PARAM_LOB;
        break;

    default:
        column->param_type = PDO_PARAM_STR;
    }

    return true;
}

bool PDOPgSqlStatement::getColumn(int colno, Variant &value)
{
    if (!this->result)
    {
        return false;
    }
    char *ptr;
    int len;


    /* We have already increased count by 1 in pgsql_stmt_fetch() */
    if (PQgetisnull(this->result, this->current_row - 1, colno))   /* Check if we got NULL */
    {
        ptr = NULL;
        len = 0;
    }
    else
    {
        ptr = PQgetvalue(this->result, this->current_row - 1, colno);
        len = PQgetlength(this->result, this->current_row - 1, colno);
        PDOPgColumn *column = columns[colno].toObject().getTyped<PDOPgColumn>();


        switch(column->param_type)
        {

        case PDO_PARAM_INT:
            /***ptr = (char *) &(atol(ptr));
            *len = sizeof(long);
            break;
            **/
        case PDO_PARAM_BOOL:
            /**         bool tmpVal = (*ptr == 't' ? 1: 0);
                     *ptr = (char *) &(tmpVal);
                     *len = sizeof(zend_bool);
                     break;
            **/
        case PDO_PARAM_LOB:
            /**if (this->cols[colno].pgsql_type == OIDOID)
            {
                char *end_ptr;
                Oid oid = (Oid)strtoul(*ptr, &end_ptr, 10);
                int loid = lo_open(this->H->server, oid, INV_READ);
                if (loid >= 0)
                {
                    *ptr = (char*)pdo_pgsql_create_lob_stream(stmt->dbh, loid, oid TSRMLS_CC);
                    *len = 0;
                    return *ptr ? 1 : 0;
                }
                *ptr = NULL;
                *len = 0;
                return 0;
            }
            else
            {
                char *tmp_ptr = PQunescapeBytea(*ptr, &tmp_len);
                if (!tmp_ptr)
                {
                    *len = 0;
                    return 0;
                }
                if (!tmp_len)
                {
                    *ptr = (char *)php_stream_memory_open(TEMP_STREAM_READONLY, "", 0);
                    PQfreemem(tmp_ptr);
                    *len = 0;
                }
                else
                {
                    *ptr = estrndup(tmp_ptr, tmp_len);
                    PQfreemem(tmp_ptr);
                    *len = tmp_len;
                    *caller_frees = 1;
                }
            }
            break;**/
        case PDO_PARAM_NULL:
        case PDO_PARAM_STR:
        case PDO_PARAM_STMT:
        case PDO_PARAM_INPUT_OUTPUT:
        case PDO_PARAM_ZVAL:
        default:
            break;
        }
        value = String(ptr, len, CopyString);

    }

    return 1;
}

bool PDOPgSqlStatement::paramHook(PDOBoundParam *param,
                                  PDOParamEvent event_type)
{
    if (this->stmt_name!=NULL && param->is_param)
    {
        switch (event_type)
        {
        case PDO_PARAM_EVT_FREE:
            if (param->driver_data)
            {
                free(param->driver_data);
            }
            break;

        case PDO_PARAM_EVT_NORMALIZE:
            /* decode name from $1, $2 into 0, 1 etc. */
            if (param->name.size()>0)
            {
                if (param->name.c_str()[0] == '$')
                {
                    param->paramno = atoi(param->name.c_str() + 1);
                }
                else
                {
                    ArrayData *data = this->bound_param_map.get();
                    if (!this->bound_param_map.empty() && true == data->exists(
                                param->name))
                    {
                        Variant v = data->get(String(
                                                  param->name));
                        String tmp = v.asStrRef();
                        param->paramno = atoi(tmp.c_str() + 1) - 1;
                    }
                    else
                    {
                        pdo_raise_impl_error(this->dbh, this, "HY093", param->name TSRMLS_CC);
                        return false;
                    }
                }
            }
            break;

        case PDO_PARAM_EVT_ALLOC:
        case PDO_PARAM_EVT_EXEC_POST:
        case PDO_PARAM_EVT_FETCH_PRE:
        case PDO_PARAM_EVT_FETCH_POST:
            /* work is handled by EVT_NORMALIZE */
            return true;

        case PDO_PARAM_EVT_EXEC_PRE:
            if (this->bound_param_map.empty())
            {
                return false;
            }
            if (!this->param_values)
            {
                this->param_values = (const char**)malloc(this->bound_param_map.size()*sizeof(char*));
                this->param_lengths = (int*)malloc(this->bound_param_map.size()*sizeof(int));
                this->param_formats = (int*)malloc(this->bound_param_map.size()*sizeof(int));
                this->param_types = (Oid*)malloc(this->bound_param_map.size()*sizeof(Oid));
            }
            if (param->paramno >= 0)
            {
                if (param->paramno > this->bound_param_map.size())
                {
                    this->m_conn->handleError("HY105",PGRES_FATAL_ERROR,__FILE__,__LINE__);
                    return false;
                }

                if (PDO_PARAM_TYPE(param->param_type) == PDO_PARAM_LOB &&
                        param->parameter.isResource())
                {
                    /**php_stream *stm;
                    php_stream_from_zval_no_verify(stm, &param->parameter);
                    if (stm)
                    {
                        if (php_stream_is(stm, &pdo_pgsql_lob_stream_ops))
                        {
                            struct pdo_pgsql_lob_self *self = (struct pdo_pgsql_lob_self*)stm->abstract;
                            pdo_pgsql_bound_param *P = param->driver_data;

                            if (P == NULL)
                            {
                                P = ecalloc(1, sizeof(*P));
                                param->driver_data = P;
                            }
                            P->oid = htonl(self->oid);
                            this->param_values[param->paramno] = (char*)&P->oid;
                            this->param_lengths[param->paramno] = sizeof(P->oid);
                            this->param_formats[param->paramno] = 1;
                            this->param_types[param->paramno] = OIDOID;
                            return 1;
                        }
                        else
                        {
                            int len;

                            SEPARATE_ZVAL_IF_NOT_REF(&param->parameter);
                            Z_TYPE_P(param->parameter) = IS_STRING;

                            if ((len = php_stream_copy_to_mem(stm, &Z_STRVAL_P(param->parameter), PHP_STREAM_COPY_ALL, 0)) > 0)
                            {
                                Z_STRLEN_P(param->parameter) = len;
                            }
                            else
                            {
                                ZVAL_EMPTY_STRING(param->parameter);
                            }
                        }
                    }
                    else
                    {
                        this->m_conn->handleError("HY105",PGRES_FATAL_ERROR,__FILE__,__LINE__);
                        return 0;
                    }**/
                }

                if (PDO_PARAM_TYPE(param->param_type) == PDO_PARAM_NULL ||
                        param->parameter.isNull())
                {
                    this->param_values[param->paramno] = NULL;
                    this->param_lengths[param->paramno] = 0;
                }
                else if (param->parameter.isBoolean())
                {
                    this->param_values[param->paramno] = param->parameter.asBooleanVal() ? "t" : "f";
                    this->param_lengths[param->paramno] = 1;
                    this->param_formats[param->paramno] = 0;
                }
                else
                {
                    String tmp = param->parameter.toString();
                    this->param_values[param->paramno] = tmp.c_str();
                    this->param_lengths[param->paramno] = tmp.size();
                    this->param_formats[param->paramno] = 0;
                }

                if (PDO_PARAM_TYPE(param->param_type) == PDO_PARAM_LOB)
                {
                    this->param_types[param->paramno] = 0;
                    this->param_formats[param->paramno] = 1;
                }
                else
                {
                    this->param_types[param->paramno] = 0;
                }
            }
            break;
        }
    }
    return true;
}

bool PDOPgSqlStatement::getColumnMeta(int64 colno, Array &return_value)
{
    Logger::Error("getColumnMeta");
    return false;
}

bool PDOPgSqlStatement::nextRowset()
{

    Logger::Error("nextRowset");
    return false;
}

bool PDOPgSqlStatement::cursorCloser()
{
    return true;
}

/**
 * Creates a DB connection
 **/
bool PDOPgSqlConnection::create(CArrRef options)
{
    std::replace( data_source.begin(), data_source.end(), ';', ' ');
    if(username.length()>0)
    {
        data_source.append(" user=").append(username).append("");
    }
    if(password.length()>0)
    {
        data_source.append(" password=").append(password).append("");
    }
    m_server = PQconnectdb(data_source.c_str());
    if(PQstatus(m_server)!=CONNECTION_OK)
    {
        handleError(PHP_PDO_PGSQL_CONNECTION_FAILURE_SQLSTATE,PGRES_FATAL_ERROR,__FILE__,__LINE__);
        return false;
    }
    return true;
}

int PDOPgSqlConnection::handleError(const char *codeString,int codeInt,const char *file, int line)
{
    throw_pdo_exception(null, null, "SQLSTATE[%s] [%d] %s",codeString,
                        codeInt,  PQerrorMessage(m_server));

    return -1;
}



///////////////////////////////////////////////////////////////////////////////

PDOPgSql::PDOPgSql() : PDODriver("pgsql")
{
}

PDOConnection *PDOPgSql::createConnectionObject()
{
    return new PDOPgSqlConnection();
}

///////////////////////////////////////////////////////////////////////////////
}

