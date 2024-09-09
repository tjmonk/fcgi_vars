/*==============================================================================
MIT License

Copyright (c) 2023 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup fcgi_vars fcgi_vars
 * @brief Fast CGI Interface for variable queries
 * @{
 */

/*============================================================================*/
/*!
@file fcgi_vars.c

    FCGI Variables

    The fcgi_vars Application provides a Fast CGI interface to support
    variable queries to the back-end variable server via a web services
    end point.  It can be interfaced via a web server such as lighttpd.

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <pwd.h>
#include <varserver/varserver.h>
#include <varserver/varcache.h>
#include <varserver/varfp.h>
#include <sessionmgr/sessionmgr.h>
#include <fcgi_stdio.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*! Maximum POST content length */
#define MAX_POST_LENGTH         1024L

/*! no session info found in HTTP headers */
#define ERROR_NO_SESSION_INFO   0x01

/*! session validation failed */
#define ERROR_SESSION_VALIDATION 0x02

/*! cannot update varserver user */
#define ERROR_UPDATE_USER 0x04

/*! No query specified */
#define ERROR_NO_QUERY 0x08

/*! Authentication failure */
#define ERROR_AUTHENTICATION 0x10

/*! cache query error */
#define ERROR_CACHE_QUERY 0x20

/*! data query error */
#define ERROR_DATA_QUERY 0x40

/*! failed to set user id */
#define ERROR_SET_UID 0x80

/*! variable not found error */
#define ERROR_VARIABLE_NOT_FOUND 0x100

/*! cache adding error */
#define ERROR_CACHE_ADD 0x200

/*! error read only */
#define ERROR_READ_ONLY 0x400

/*! no content length specified */
#define ERROR_NO_CONTENT_LENGTH 0x800

/*! illegal content length specified */
#define ERROR_INVALID_CONTENT_LENGTH 0x1000

/*! unsupported request */
#define ERROR_UNSUPPORTED_REQUEST 0x2000

/*! node for managing a list of variable caches */
typedef struct _cacheNode
{
    /*! pointer to the variable cache */
    VarCache *pVarCache;

    /*! pointer to the name of the variable cache */
    char *pName;

    /*! pointer to the next cache in the list */
    struct _cacheNode *pNext;
} CacheNode;

/*! FCGIVars state */
typedef struct _FCGIVarsState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! maximum POST data length */
    size_t maxPostLength;

    /*! POST buffer */
    char *postBuffer;

    /*! Variable Output Cache */
    VarCache *pVarCache;

    /*! list of variable caches */
    CacheNode *pCacheList;

    /*! Variable Output buffer */
    VarFP *pVarFP;

    /*! Unauthenticated user */
    uid_t unauthenticated_user;

    /*! user id of current user */
    uid_t uid;

    /*! user id of previous user */
    uid_t olduid;

    /*! count of the output variables */
    size_t outputCount;

    /*! verbose flag */
    bool verbose;

    /*! read only flag */
    bool readonly;

    /*! authentication required */
    bool auth;

    /*! variable flags */
    uint32_t flags;

    /*! error code to report to client */
    uint32_t errorCode;

} FCGIVarsState;


/*! query processing functions */
typedef struct _queryFunc
{
    /*! query tag string to associate with a tag processing function */
    char *tag;

    /*! pointer to the function to handle the tag data */
    int (*pTagFn)(FCGIVarsState *, char *);

} QueryFunc;

/*! Handler function */
typedef int (*HandlerFunction)(FCGIVarsState *);

/*! FCGI Handler function */
typedef struct _fcgi_handler
{
    /*! handler name */
    char *handler;

    /*! handler function */
    HandlerFunction fn;
} FCGIHandler;

/*==============================================================================
        Private function declarations
==============================================================================*/

int main(int argc, char **argv);
static int InitState( FCGIVarsState *pState );
static int ProcessOptions( int argC, char *argV[], FCGIVarsState *pState );
static uid_t GetUserID( const char *username );
static void usage( char *cmdname );
static int ProcessRequests( FCGIVarsState *pState,
                            FCGIHandler *pFCGIHandlers,
                            size_t numHandlers );

static int ProcessGETRequest( FCGIVarsState *pState );
static int ProcessPOSTRequest( FCGIVarsState *pState );
static int GetPOSTData( FCGIVarsState *pState, size_t length );
static int ProcessUnsupportedRequest( FCGIVarsState *pState );
static int ProcessQuery( FCGIVarsState *pState, char *request );

static int CheckAuthentication( FCGIVarsState *pState );
static int SetUser( FCGIVarsState *pState, uid_t uid );
static int RestoreOldUser( FCGIVarsState *pState );

static int ProcessQueryFunctions( FCGIVarsState *pState,
                                  char *query,
                                  QueryFunc *pFns,
                                  int numFuncs );

static int InvokeQueryFunction( FCGIVarsState *pState,
                                char *query,
                                QueryFunc *pFns,
                                int numFuncs );

static int ProcessNameQuery( FCGIVarsState *pState, char *query );
static int ProcessSetRequest( FCGIVarsState *pState, char *query );
static int ProcessSetTuple( FCGIVarsState *pState, char *pTuple );
static int ProcessMatchQuery( FCGIVarsState *pState, char *query );
static int ProcessTagsQuery( FCGIVarsState *pState, char *query );
static int ProcessInstanceQuery( FCGIVarsState *pState, char *query );
static int ProcessSelectCache( FCGIVarsState *pState, char *name );
static int ProcessSelectClearCache( FCGIVarsState *pState, char *name );

static VAR_HANDLE CheckFlags( FCGIVarsState *pState, VAR_HANDLE hVar );

static int AllocatePOSTBuffer( FCGIVarsState *pState );
static int ClearPOSTBuffer( FCGIVarsState *pState );
static int SendVarsResponse( FCGIVarsState *pState );
static int OutputVar( VAR_HANDLE hVar, void *arg );
static void SetupTerminationHandler( void );
static void TerminationHandler( int signum, siginfo_t *info, void *ptr );

static HandlerFunction GetHandlerFunction( char *method,
                                           FCGIHandler *pFCGIHandlers,
                                           size_t numHandlers );

static int OutputJSONVar( char prefix, VarInfo *info, char *value );
static void SendVarsHeader( void );
static void SendVarsFooter( int count );
static int ErrorResponse( int status,  char *description, uint32_t errorCode );
static bool IsJSON( char *value );

static VarCache *GetCache( FCGIVarsState *pState, char *name );
static VarCache *FindCache( FCGIVarsState *pState, char *name );
static VarCache *AddCache( FCGIVarsState *pState, char *name );
static CacheNode *NewCache( char *name );

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! array of HTTP method handlers */
FCGIHandler methodHandlers[] =
{
    { "GET", ProcessGETRequest },
    { "POST", ProcessPOSTRequest },
    { "*", ProcessUnsupportedRequest }
};

/* FCGI Vars State object */
FCGIVarsState state;

/*==============================================================================
        Private function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the fcgi_vars application

    The main function starts the fcgi_vars application

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return none

==============================================================================*/
int main(int argc, char **argv)
{
    /* initialize the FCGI Vars state */
    InitState( &state );

    /* set up the termination handler */
    SetupTerminationHandler();

    /* process the command line options */
    ProcessOptions( argc, argv, &state );

    /* open a VarFP object for printing */
    state.pVarFP = VARFP_Open("fcgi_var", 256 * 1024 );

    /* get a handle to the variable server */
    state.hVarServer = VARSERVER_Open();
    if( state.hVarServer != NULL )
    {
        if ( state.auth == true )
        {
            VARSERVER_SetGroup();
        }

        /* allocate memory for the POST data buffer */
        if( AllocatePOSTBuffer( &state ) == EOK )
        {
            /* process FCGI requests */
            ProcessRequests( &state,
                                methodHandlers,
                                sizeof(methodHandlers) / sizeof(FCGIHandler) );
        }
        else
        {
            syslog( LOG_ERR, "Cannot allocate POST buffer" );
        }

        if ( VARSERVER_Close( state.hVarServer ) == EOK )
        {
            state.hVarServer = NULL;
        }
    }
    else
    {
        syslog( LOG_ERR, "Cannot open variable server" );
    }

    if ( VARFP_Close( state.pVarFP ) == EOK )
    {
        state.pVarFP = NULL;
    }

    return 0;
}

/*============================================================================*/
/*  InitState                                                                 */
/*!
    Initialize the FCGIVars state

    The InitState function initializes the FCGIVars state object

    @param[in]
        pState
            pointer to the FCGIVarsState object to initialize

    @retval EOK the FCGIVarsState object was successfully initialized
    @retval EINVAL invalid arguments

==============================================================================*/
static int InitState( FCGIVarsState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        /* clear the state */
        memset( pState, 0, sizeof( FCGIVarsState ) );

        /* set the default POST content length */
        pState->maxPostLength = MAX_POST_LENGTH;

        /* set the unauthenticated user id */
        pState->unauthenticated_user = (uid_t)-1;

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message
    to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h] "
                " [-h] : display this help"
                " [-v] : verbose output"
                " [-r] : readonly"
                " [-f <flag list>] : comma separated flag list"
                " [-l <max POST length>] : maximum POST data length",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the FCGIVarsState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK options processed successfully
    @retval ENOTSUP unsupported option
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], FCGIVarsState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "hvl:rf:au:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        result = EOK;

        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'v':
                    pState->verbose = true;
                    break;

                case 'l':
                    pState->maxPostLength = strtoul( optarg, NULL, 0 );
                    break;

                case 'a':
                    pState->auth = true;
                    break;

                case 'r':
                    pState->readonly = true;
                    break;

                case 'f':
                    VARSERVER_StrToFlags(optarg, &pState->flags);
                    break;

                case 'h':
                    usage( argV[0] );
                    break;

                case 'u':
                    pState->unauthenticated_user = GetUserID(optarg);
                    break;

                default:
                    result = ENOTSUP;
                    break;

            }
        }
    }

    return result;
}

/*============================================================================*/
/*  GetUserID                                                                 */
/*!
    Get the user id associated with a user name

    The GetUserID function gets the user id associated with a user name
    from the password database.

    @param[in]
        username
            name of the user to lookup


    @retval user id associated with the username
    @retval (uid_t)-1 if the user name was not found

==============================================================================*/
static uid_t GetUserID( const char *username )
{
    uid_t uid = (uid_t)-1;
    struct passwd *passwordEntry = NULL;

    if ( username != NULL )
    {
        passwordEntry = getpwnam( username );
        if ( passwordEntry != NULL )
        {
            uid = passwordEntry->pw_uid;
        }
    }

    return uid;
}

/*============================================================================*/
/*  ProcessRequests                                                           */
/*!
    Process incoming Fast CGI requests

    The ProcessRequests function waits for incoming FCGI requests
    and processes them according to their request method.
    Typically this function will not exit, as doing so will terminate
    the FCGI interface.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        pFCGIHandlers
            pointer to an array of FCGIHandler objects which link method
            names (eg GET, POST) with their method handling functions.

    @param[in]
        numHandlers
            number of handlers in the array of FCGIHandler objects

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessRequests( FCGIVarsState *pState,
                            FCGIHandler *pFCGIHandlers,
                            size_t numHandlers )
{
    int result = EINVAL;
    char *method;
    HandlerFunction fn = NULL;

    if ( ( pState != NULL ) &&
         ( pFCGIHandlers != NULL ) &&
         ( numHandlers > 0 ) )
    {
        /* wait for an FCGI request */
        while( FCGI_Accept() >= 0 )
        {
            /* reset error code */
            pState->errorCode = 0;

            /* check the request method */
            method = getenv("REQUEST_METHOD");
            if ( method != NULL )
            {
                /* get the handler associated with the method */
                fn = GetHandlerFunction( method, pFCGIHandlers, numHandlers );
                if ( fn != NULL )
                {
                    /* invoke the handler */
                    result = fn( pState );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  GetHandlerFunction                                                        */
/*!
    Get the handler function for the specified method

    The GetHandlerFunction function looks up the processing function
    associated with the specified HTTP method.

    The handler functions are passed in via the pFCGIHandler pointer

    @param[in]
        method
            pointer to the method name, eg "GET", "POST"

    @param[in]
        pFCGIHandlers
            pointer to the FCGI method handling functions

    @param[in]
        numHandlers
            number of handlers in the method handling function array pointed
            to by pFCGIHandler

    @retval pointer to the method handler
    @retval NULL no method handler could be found

==============================================================================*/
static HandlerFunction GetHandlerFunction( char *method,
                                           FCGIHandler *pFCGIHandlers,
                                           size_t numHandlers )
{
    size_t i;
    FCGIHandler *pFCGIHandler;
    HandlerFunction fn = NULL;

    if ( ( method != NULL ) &&
         ( pFCGIHandlers != NULL ) &&
         ( numHandlers > 0 ) )
    {
        /* iterate through the FCGI method handlers */
        for ( i = 0; i < numHandlers ; i++ )
        {
            /* get a pointer to the current method handler */
            pFCGIHandler = &pFCGIHandlers[i];
            if ( pFCGIHandler != NULL )
            {
                /* check if it matches the REQUEST_METHOD or the
                 * wild card */
                if ( ( strcmp( pFCGIHandler->handler, method ) == 0 ) ||
                     ( strcmp( pFCGIHandler->handler, "*" ) == 0 ) )
                {
                    /* get a pointer to the handler function */
                    fn = pFCGIHandler->fn;
                    break;
                }
            }
        }
    }

    return fn;
}

/*============================================================================*/
/*  SendVarsResponse                                                          */
/*!
    Send a variable query response

    The SendVars response function checks the variable cache
    in the FCGIVarsState and if it has any data, it is
    transmitted as a JSON array.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK response sent successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int SendVarsResponse( FCGIVarsState *pState )
{
    int result = EINVAL;
    VarCache *pCache;

    if ( pState != NULL )
    {
        /* get a pointer to the variable cache */
        pCache = pState->pVarCache;

    	SendVarsHeader();

        /* initialize the output count */
        pState->outputCount = 0;

        /* map the OutputVar function across the variable cache */
        VARCACHE_Map( pCache, OutputVar, (void *)pState );

        SendVarsFooter(pState->outputCount);

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  ProcessGETRequest                                                         */
/*!
    Process a Fast CGI GET request

    The ProcessGETRequest function processes a single FCGI GET request
    contained in the QUERY_STRING environment variable

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessGETRequest( FCGIVarsState *pState )
{
    int result = EINVAL;
    char *query;

    if ( pState != NULL )
    {
        /* get the query string */
        query = getenv("QUERY_STRING");

        /* process the request */
        result = ProcessQuery( pState, query );
        if( result == EOK )
        {
            result = SendVarsResponse( pState );
        }
        else
        {
            switch( result )
            {
                case EPERM:
                case EACCES:
                    result = ErrorResponse( 401,
                                            "Unauthorized",
                                            pState->errorCode );
                    break;

                default:
                    result = ErrorResponse( 400,
                                            "Bad request",
                                            pState->errorCode );
                    break;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessPOSTRequest                                                        */
/*!
    Process a Fast CGI POST request

    The ProcessPOSTRequest function processes a single FCGI POST request
    where the request is contained in the body of the message

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessPOSTRequest( FCGIVarsState *pState )
{
    int result = EINVAL;
    char *contentLength;
    size_t length;

    if ( pState != NULL )
    {
        /* get the content length */
        contentLength = getenv("CONTENT_LENGTH");
        if( contentLength != NULL )
        {
            /* convert the content length to an integer */
            length = strtoul(contentLength, NULL, 0);
            if ( ( length > 0 ) && ( length <= pState->maxPostLength ) )
            {
                /* read the query from the POST Data */
                result = GetPOSTData( pState, length );
                if( result == EOK )
                {
                    /* Process the request */
                    result = ProcessQuery( pState, pState->postBuffer );
                    if ( result == EOK )
                    {
                        result = SendVarsResponse( pState );
                    }

                    /* clear the POST buffer.  This is critical since
                     * the buffer must be zeroed before the next read in order
                     * to make sure it is correctly NUL terminated */
                    ClearPOSTBuffer( pState );
                }
            }
            else
            {
                /* content length is too large (or too small) */
                pState->errorCode |= ERROR_INVALID_CONTENT_LENGTH;
                ErrorResponse( 413,
                               "Invalid Content-Length",
                               pState->errorCode );
            }
        }
        else
        {
            /* unable to get content length */
            pState->errorCode |= ERROR_NO_CONTENT_LENGTH;
            ErrorResponse( 413,
                           "Invalid Content-Length",
                           pState->errorCode );
        }
    }

    return result;
}

/*============================================================================*/
/*  GetPOSTData                                                               */
/*!
    Read the POST data from a Fast CGI POST request

    The GetPOSTData function reads the POST data into the POST data
    buffer in the FCGIVarsState object.  It is assumed that the
    content length has already been determined and is specified
    in the length parameter.

    Note that this function does NOT NUL terminate the input buffer.
    This buffer is assumed to be zeroed before each read

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        length
            content-length bytes to read

    @retval EOK request processed successfully
    @retval ENXIO I/O error
    @retval ENOMEM not enough memory to read the POST data
    @retval EINVAL invalid arguments

==============================================================================*/
static int GetPOSTData( FCGIVarsState *pState, size_t length )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if( length <= pState->maxPostLength )
        {
            /* read content-length bytes of data */
            if ( FCGI_fread( pState->postBuffer, length, 1, FCGI_stdin ) == 1 )
            {
                /* content-length bytes of data successfully read */
                result = EOK;
            }
            else
            {
                /* unable to read content-length bytes of data */
                result = ENXIO;
            }
        }
        else
        {
            /* not enough memory to read content-length bytes of data */
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessUnsupportedRequest                                                 */
/*!
    Process a Fast CGI request using an unsupport request method

    The ProcessUnsupportedRequest function processes a single FCGI request
    where the request method is not supported

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessUnsupportedRequest( FCGIVarsState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        pState->errorCode |= ERROR_UNSUPPORTED_REQUEST;

        result = ErrorResponse( 405,
                                "Method Not Allowed",
                                pState->errorCode );
    }

    return result;
}

/*============================================================================*/
/*  ProcessQuery                                                              */
/*!
    Process a Variable Query

    The ProcessQuery function processes a single variable query

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessQuery( FCGIVarsState *pState, char *query )
{
    int result = EINVAL;
    int n1;
    int n2;
    int rc;

    QueryFunc fn1[] =
    {
        { "cache=", &ProcessSelectCache },
        { "clearcache=", &ProcessSelectClearCache }
    };

    QueryFunc fn2[] =
    {
        { "name=", &ProcessNameQuery },
        { "match=", &ProcessMatchQuery },
        { "tags=", &ProcessTagsQuery },
        { "instance=", &ProcessInstanceQuery },
        { "set=", &ProcessSetRequest }
    };

    /* count the number of query processing functions */
    n1 = sizeof( fn1 ) / sizeof( QueryFunc );
    n2 = sizeof( fn2 ) / sizeof( QueryFunc );

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        result = EOK;

        result = CheckAuthentication( pState );
        if ( result == EOK )
        {
            /* select the default cache */
            ProcessSelectCache( pState, "default" );

            /* clear the cache */
            VARCACHE_Clear( pState->pVarCache );

            /* set up query parameters, eg cache name */
            result = ProcessQueryFunctions( pState,
                                            query,
                                            fn1,
                                            n1 );
            if ( result == EOK )
            {
                /* perform variable query */
                result = ProcessQueryFunctions( pState,
                                                query,
                                                fn2,
                                                n2 );
                if ( result == EOK )
                {
                    pState->errorCode |= ERROR_DATA_QUERY;
                }
            }
            else
            {
                pState->errorCode |= ERROR_CACHE_QUERY;
            }

            /* restore the original process user id before it was changed */
            rc = RestoreOldUser( pState );
            if ( ( result == EOK ) && ( rc != EOK ) )
            {
                result = rc;
            }
        }
        else
        {
            pState->errorCode |= ERROR_AUTHENTICATION;
        }
    }
    else
    {
        /* cannot find query string */
        pState->errorCode |= ERROR_NO_QUERY;
    }

    return result;
}

/*============================================================================*/
/*  CheckAuthentication                                                       */
/*!
    Check if requesting user is authenticated

    The CheckAuthentication function checks if the current user is
    authenticated by extracting the session identifier from the HTTP
    Authorization cookie and checking with the session manager to
    see if it is valid.  If the session is valid, the varserver
    group list is updated to reflect the groups of the current user.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK the current user is valid or authentication is disabled
    @retval EACCES access is denied
    @retval EINVAL invalid arguments

==============================================================================*/
static int CheckAuthentication( FCGIVarsState *pState )
{
    int result = EINVAL;
    char *pSession;
    char session[SESSION_ID_LEN+1];
    uid_t uid;

    if ( pState != NULL )
    {
        if ( pState->auth == true  )
        {
            pState->olduid = getuid();

            /* get the session id from the HTTP cookie */
            pSession = SESSIONMGR_GetSessionFromCookie(
                            getenv("HTTP_COOKIE"),
                            session,
                            sizeof(session) );
            if ( pSession != NULL )
            {
                /* check if the session is valid */
                result = SESSIONMGR_Validate( pSession, &uid );
                if ( result == EOK )
                {
                    result = SetUser( pState, uid );
                    if ( result != EOK )
                    {
                        result = EACCES;
                    }
                }
                else
                {
                    pState->errorCode |= ERROR_SESSION_VALIDATION;

                    syslog( LOG_INFO,
                            "Failed to validate session %8.8s",
                            pSession );

                    result = EACCES;
                }
            }
            else if ( pState->unauthenticated_user != (uid_t)-1)
            {
                result = SetUser( pState, pState->unauthenticated_user );
                if ( result != EOK )
                {
                    syslog( LOG_INFO,
                            "Failed to set unauthenticated user %d",
                            pState->unauthenticated_user );

                    pState->errorCode |= ERROR_SESSION_VALIDATION;

                    result = EACCES;
                }
            }
            else
            {
                pState->errorCode |= ERROR_NO_SESSION_INFO;

                syslog( LOG_INFO, "No session info");
                result = EACCES;
            }
        }
        else
        {
            /* no authentication necessary */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  SetUser                                                                   */
/*!
    Set the user for the current transaction to the specified uid

    The SetUser function sets the user identifier for the current
    transaction to the specified uid.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        uid
            user id for the current transaction

    @retval EOK the user id was set correctly
    @retval ENOTSUP invalid user id
    @retval other error from VARSERVER_UpdateUser or seteuid

==============================================================================*/
static int SetUser( FCGIVarsState *pState, uid_t uid )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if ( uid != (uid_t)-1 )
        {
            /* store the uid of the current user */
            pState->uid = uid;
            if ( seteuid( uid ) != 0 )
            {
                pState->errorCode |= ERROR_SET_UID;
                result = errno;
                syslog( LOG_ERR, "Failed to set uid to %d", uid );
            }
            else
            {
                /* update the varserver user */
                result = VARSERVER_UpdateUser( pState->hVarServer );
                if ( result != EOK )
                {
                    pState->errorCode |= ERROR_UPDATE_USER;
                }
            }
        }
        else
        {
            syslog( LOG_ERR, "Invalid uid %d", uid );
            pState->errorCode = ERROR_SET_UID;
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  RestoreOldUser                                                            */
/*!
    Restore the original user for the fcgi_vars process

    The RestoreOldUser function restores the original user for the
    fcgi_vars process before it was changed by a session authentication

    @param[in]
        pState
            pointer to the FCGIVars state object

    @retval EOK the original user was restored, or authentication is disabled
    @retval EINVAL invalid arguments
    @retval other error from seteuid

==============================================================================*/
static int RestoreOldUser( FCGIVarsState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if ( pState->auth == true )
        {
            if ( seteuid(pState->olduid) == 0 )
            {
                result = EOK;
            }
            else
            {
                result = errno;

                syslog( LOG_ERR,
                        "Failed to restore uid to %d",
                        pState->olduid );
            }
        }
        else
        {
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessQueryFunctions                                                     */
/*!
    Process Variable Query functions

    The ProcessQueryFunctions function applies an array of functions to the
    variable query string, applying the functions from the function list
    as appropriate.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the query

    @param[in]
        pFns
            array of query processing functions to possibly apply

    @param[in]
        numFuncs
            number of functions in the pFns array

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessQueryFunctions( FCGIVarsState *pState,
                                  char *query,
                                  QueryFunc *pFns,
                                  int numFuncs )
{
    int result = EINVAL;
    char *mutquery;
    char *pQuery;
    char *save = NULL;
    int rc;

    if ( ( pState != NULL ) && ( query != NULL ) && ( pFns != NULL ))
    {
        /* assume everything is ok, until it is not */
        result = EOK;

        /* create a copy of the query string we can freely mutate */
        mutquery = strdup( query );
        if ( mutquery != NULL )
        {
            /* split the query on "&" */
            pQuery = strtok_r( mutquery, "&", &save );
            while ( pQuery != NULL )
            {
                /* invoked the query function */
                rc = InvokeQueryFunction( pState, pQuery, pFns, numFuncs );
                if ( rc != EOK )
                {
                    result = rc;
                }

                /* get the next token */
                pQuery = strtok_r( NULL, "&", &save );
            }

            /* free the mutable query string */
            free( mutquery );
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  InvokeQueryFunction                                                       */
/*!
    Invoke a Variable Query function

    The InvokeQueryFunction function scans the list of supplied functions
    and compares that against the supplied query argument, and invokes
    the function which matches the supplied query argument.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the query argument

    @param[in]
        pFns
            array of query processing functions to possibly apply

    @param[in]
        numFuncs
            number of functions in the pFns array

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int InvokeQueryFunction( FCGIVarsState *pState,
                                char *query,
                                QueryFunc *pFns,
                                int numFuncs )
{
    int result = EINVAL;
    int i;
    char *tag;
    int (*pTagFn)( FCGIVarsState *, char *) = NULL;
    size_t offset;

    if ( ( pState != NULL ) && ( query != NULL ) && ( pFns != NULL ) )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        /* iterate through the query handlers */
        for ( i=0; i < numFuncs ; i++ )
        {
            /* get a pointer to the tag to search for */
            tag = pFns[i].tag;

            /* check if our current token starts with this tag */
            if( strstr( query, tag ) == query )
            {
                /* get a pointer to the query function */
                pTagFn = pFns[i].pTagFn;
                if( pTagFn != NULL )
                {
                    /* get the start of the query data */
                    offset = strlen( tag );

                    /* invoke the query handler */
                    result = pTagFn( pState, &query[offset] );
                    break;
                }
            }
        }
    }

    return result;

}

/*============================================================================*/
/*  ProcessNameQuery                                                          */
/*!
    Process a Variable Name Query

    The ProcessNameQuery function processes a list of variable names
    separated by commas and appends the variable handles to the FCGIVarsState
    VarCache object.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the comma separated list of variable names to query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessNameQuery( FCGIVarsState *pState, char *query )
{
    int result = EINVAL;
    char *save;
    char *pName;
    VAR_HANDLE hVar;
    int rc;

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        result = EOK;

        /* get a pointer to the name */
        pName = strtok_r( query, ",", &save );
        while ( pName != NULL )
        {
            /* look up the variable using its name */
            hVar = VAR_FindByName( pState->hVarServer, pName );
            hVar = CheckFlags( pState, hVar );
            if( hVar != VAR_INVALID )
            {
                /* add the variable to the variable cache */
                rc = VARCACHE_AddUnique( pState->pVarCache, hVar );
                if( rc != EOK )
                {
                    pState->errorCode |= ERROR_CACHE_ADD;
                    result = rc;
                }
            }
            else
            {
                /* variable not found */
                pState->errorCode |= ERROR_VARIABLE_NOT_FOUND;
                result = ENOENT;
            }

            /* get the next name */
            pName = strtok_r( NULL, ",", &save );
        }
    }

    return result;
}

/*============================================================================*/
/*  CheckFlags                                                                */
/*!
    Filter variables based on their flags

    The CheckFlags function will query the specified varserver variable's
    flags to see if one or more of the flags match those specified to be
    handled by this instance of fcgi_vars.  If one or more flags match
    then the variable may be processed, otherwise it will be skipped.

    @param[in]
        pState
            pointer to the FCGIVars state object that contains the flags filter

    @param[in]
        hVar
            handle to the variable being processed

    @retval hVar if the variable passed the flags filter
    @retval VAR_INVALID the variable did not pass the filter

==============================================================================*/
static VAR_HANDLE CheckFlags( FCGIVarsState *pState, VAR_HANDLE hVar )
{
    VAR_HANDLE handle = VAR_INVALID;
    uint32_t flags;
    int rc;

    if ( ( pState != NULL ) &&
         ( hVar != VAR_INVALID ) )
    {
        if ( pState->flags == 0 )
        {
            handle = hVar;
        }
        else
        {
            /* get the flags for the variable from the varserver */
            rc = VAR_GetFlags( pState->hVarServer, hVar, &flags );
            if ( rc == EOK )
            {
                /* check if the flags for the variable contain
                   ANY of the flags specified */
                if ( pState->flags & flags )
                {
                    /* if any of the flags are found, allow the query */
                    handle = hVar;
                }
            }
        }
    }

    return handle;
}

/*============================================================================*/
/*  ProcessSetRequest                                                         */
/*!
    Process a Variable Set Request

    The ProcessSetRequest function processes a list of variable names/values
    separated by commas and sets each variable to the requested value.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the comma separated list of variable names/values

    @retval EOK query processed successfully
    @retval ENOTSUP one or more variables were not allowed to be set
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessSetRequest( FCGIVarsState *pState, char *query )
{
    int result = EINVAL;
    char *save;
    char *pTuple;
    int rc;

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        result = EOK;

        if ( pState->readonly == false )
        {
            /* get a pointer to the name/value tuple */
            pTuple = strtok_r( query, ",", &save );
            while ( pTuple != NULL )
            {
                /* process a set request tuple */
                rc = ProcessSetTuple( pState, pTuple );
                if ( rc != EOK )
                {
                    result = rc;
                }

                /* get the next name/value tuple */
                pTuple = strtok_r( NULL, ",", &save );
            }
        }
        else
        {
            /* don't allow sets in readonly mode */
            pState->errorCode |= ERROR_READ_ONLY;
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessSetTuple                                                           */
/*!
    Process a Variable Set Tuple

    The ProcessSetTuple function processes a variable name/value tuple in
    the form <name>=<value>

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        pTuple
            pointer to the <name>=<value> tuple

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessSetTuple( FCGIVarsState *pState, char *pTuple )
{
    int result = EINVAL;
    char *pValue;
    char *pName;
    VAR_HANDLE hVar;
    uint32_t flags = 0;

    if ( ( pState != NULL ) &&
         ( pTuple != NULL ) )
    {
        /* find and remove the '=' */
        pValue = strchr( pTuple, '=');
        if ( pValue != NULL )
        {
            *pValue++ = 0;
            pName = pTuple;

            /* look up the variable using its name */
            hVar = VAR_FindByName( pState->hVarServer, pName );
            if( hVar != VAR_INVALID )
            {
                if ( pState->flags != VARFLAG_NONE )
                {
                    VAR_GetFlags( pState->hVarServer, hVar, &flags );
                    if ( ( pState->flags & flags ) == VARFLAG_NONE )
                    {
                        return ENOTSUP;
                    }
                }
            }

            /* set the name/value */
            result = VAR_SetNameValue( pState->hVarServer,
                                       pName,
                                       pValue );
            if ( result == EOK )
            {
                /* look up the variable using its name */
                hVar = VAR_FindByName( pState->hVarServer, pName );
                if( hVar != VAR_INVALID )
                {
                    /* add the variable to the variable cache */
                    result = VARCACHE_AddUnique( pState->pVarCache, hVar );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessSelectCache                                                        */
/*!
    Select a cache

    The ProcessSelectCache function selects the specific named cache to use
    for the current query.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        name
            name of the cache to use in the current query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessSelectCache( FCGIVarsState *pState, char *name )
{
    int result = EINVAL;

    if ( ( pState != NULL ) &&
         ( name != NULL ) )
    {
        result = EOK;

        /* select the cache */
        pState->pVarCache = GetCache(  pState, name );
    }

    return result;
}

/*============================================================================*/
/*  ProcessSelectClearCache                                                   */
/*!
    Select and clear a cache

    The ProcessSelectClearCache function selects the specific named cache to use
    for the current query and clears the cache content before it is used.

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        name
            name of the cache to use in the current query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessSelectClearCache( FCGIVarsState *pState, char *name )
{
    int result = EINVAL;

    if ( ( pState != NULL ) &&
         ( name != NULL ) )
    {
        result = EOK;

        /* select the cache */
        pState->pVarCache = GetCache(  pState, name );

        /* clear the cache */
        VARCACHE_Clear( pState->pVarCache);
    }

    return result;
}


/*============================================================================*/
/*  ProcessMatchQuery                                                         */
/*!
    Process a Variable Match Query

    The ProcessMatchQuery function processes a variable match string
    and appends the variable handles to the FCGIVarsState VarCache object

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the string to match against the variable names

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessMatchQuery( FCGIVarsState *pState, char *query )
{
    int result = EINVAL;
    int rc;
    VarQuery varQuery;

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        result = EOK;

        // clear the query object
        memset( &varQuery, 0, sizeof( VarQuery ) );

        // set up the query
        if ( pState->flags != VARFLAG_NONE )
        {
            varQuery.type = QUERY_MATCH | QUERY_FLAGS;
            varQuery.flags = pState->flags;
        }
        else
        {
            varQuery.type = QUERY_MATCH;
        }

        varQuery.match = query;

        // find the first matching variable
        rc = VAR_GetFirst( pState->hVarServer, &varQuery, NULL );
        while ( rc == EOK )
        {
            if( varQuery.hVar != VAR_INVALID )
            {
                /* add the variable to the variable cache */
                VARCACHE_AddUnique( pState->pVarCache, varQuery.hVar );
            }
            else
            {
                break;
            }

            // get the next matching variable
            rc = VAR_GetNext( pState->hVarServer, &varQuery, NULL );
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessTagsQuery                                                          */
/*!
    Process a Variable Tags Query

    The ProcessTagsQuery function processes a variable tags string
    and appends the variable handles to the FCGIVarsState VarCache object

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the string to match against the variable names

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessTagsQuery( FCGIVarsState *pState, char *query )
{
    int result = EINVAL;
    int rc;
    VarQuery varQuery;
    size_t len;

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        result = EOK;

        // clear the query object
        memset( &varQuery, 0, sizeof( VarQuery ) );

        // set up the query
        if ( pState->flags != 0 )
        {
            varQuery.type = QUERY_TAGS | QUERY_FLAGS;
            varQuery.flags = pState->flags;
        }
        else
        {
            varQuery.type = QUERY_TAGS;
        }

        len = strlen( query );
        if ( len < MAX_TAGSPEC_LEN )
        {
            strcpy( varQuery.tagspec, query );
        }

        // find the first matching variable
        rc = VAR_GetFirst( pState->hVarServer, &varQuery, NULL );
        while ( rc == EOK )
        {
            if( varQuery.hVar != VAR_INVALID )
            {
                /* add the variable to the variable cache */
                VARCACHE_AddUnique( pState->pVarCache, varQuery.hVar );
            }
            else
            {
                break;
            }

            // get the next matching variable
            rc = VAR_GetNext( pState->hVarServer, &varQuery, NULL );
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessInstanceQuery                                                      */
/*!
    Process a Variable Match Query

    The ProcessInstanceQuery function processes all variables with the
    specified instance ID and appends the variable handles to the
    FCGIVarsState VarCache object

    @param[in]
        pState
            pointer to the FCGIVars state object

    @param[in]
        query
            pointer to the instance identifier string

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessInstanceQuery( FCGIVarsState *pState, char *query )
{
    int result = EINVAL;
    int rc;
    VarQuery varQuery;

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        result = EOK;

        // clear the query object
        memset( &varQuery, 0, sizeof( VarQuery ) );

        // set up the query
        varQuery.type = QUERY_INSTANCEID | QUERY_FLAGS;
        varQuery.instanceID = atol( query );
        varQuery.flags = pState->flags;

        // find the first matching variable
        rc = VAR_GetFirst( pState->hVarServer, &varQuery, NULL );
        while ( rc == EOK )
        {
            if( varQuery.hVar != VAR_INVALID )
            {
                /* add the variable to the variable cache */
                VARCACHE_AddUnique( pState->pVarCache, varQuery.hVar );
            }
            else
            {
                break;
            }

            // get the next matching variable
            rc = VAR_GetNext( pState->hVarServer, &varQuery, NULL );
        }
    }

    return result;
}

/*============================================================================*/
/*  AllocatePOSTBuffer                                                        */
/*!
    Allocate memory for the POST buffer

    The AllocatePOSTBuffer function allocates storage space on the heap
    for a buffer to contain the POST data.  It gets the requested POST
    buffer size from the FCGIVarsState object.

    @param[in]
        pState
            pointer to the FCGIVars state object containing the requested
            POST buffer size

    @retval EOK memory was successfully allocated for the POST buffer
    @retval ENOMEM could not allocate memory for the POST buffer
    @retval EINVAL invalid arguments

==============================================================================*/
static int AllocatePOSTBuffer( FCGIVarsState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if( pState->maxPostLength > 0 )
        {
            /* allocate memory for the POST buffer including a NUL terminator */
            pState->postBuffer = calloc( 1, pState->maxPostLength + 1 );
            if( pState->postBuffer != NULL )
            {
                result = EOK;
            }
            else
            {
                /* cannot allocate memory for the POST buffer */
                result = ENOMEM;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ClearPOSTBuffer                                                           */
/*!
    Zero the memory used for the POST data

    The ClearPOSTBuffer function zeros the memory used by the POST buffer
    between requests.

    @param[in]
        pState
            pointer to the FCGIVars state object containing the POST buffer.

    @retval EOK memory was successfully allocated for the POST buffer
    @retval ENOMEM the POST buffer memory was not allocated
    @retval EINVAL invalid arguments

==============================================================================*/
static int ClearPOSTBuffer( FCGIVarsState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if ( pState->postBuffer != NULL )
        {
            /* clear the post buffer (including NUL terminator) */
            memset( pState->postBuffer, 0, pState->maxPostLength + 1 );

            result = EOK;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}


/*============================================================================*/
/*  OutputVar                                                                 */
/*!
    Output Variable data

    The OutputVar function outputs a variable name/value JSON
    object.

    @param[in]
        hVar
            handle to the variable to output

    @param[in]
        arg
            handle to the FCGIVarsState object

    @retval EOK the variable was output
    @retval EINVAL invalid arguments

==============================================================================*/
static int OutputVar( VAR_HANDLE hVar, void *arg )
{
    FCGIVarsState *pState = (FCGIVarsState *)arg;
    char *pData;
    int result = EINVAL;
    int fd;
    char prefix;
    VarInfo info;
    ssize_t n;

    if ( ( pState != NULL ) &&
         ( hVar != VAR_INVALID ) )
    {
        fd = VARFP_GetFd( pState->pVarFP );

        /* get the variable info */
        if ( VAR_GetInfo( pState->hVarServer,
                          hVar,
                          &info ) == EOK )

        {
            /* print the variable value to the output buffer */
            if( VAR_Print( pState->hVarServer,
                           hVar,
                           fd ) == EOK )
            {
                /* NUL terminate */
                n = write( fd, "\0", 1 );
                if ( n != 1 )
                {
                    /* I/O error */
                    result = EIO;
                }

                /* get a handle to the output buffer */
                pData = VARFP_GetData( pState->pVarFP );
                if( pData != NULL )
                {
                    /* see if we need to prepend a comma */
                    prefix = ( pState->outputCount > 0 ) ? ',' : ' ';

                    /* output the data */
                    OutputJSONVar( prefix, &info, pData );

                    /* clear the memory */
                    pData[0] = '\0';

                    /* increment the variable count */
                    pState->outputCount++;

                    result = EOK;
                }
            }

            /* seek to the beginning of the output buffer */
            lseek( fd, 0, SEEK_SET );
        }
    }

    return result;
}

/*============================================================================*/
/*  SetupTerminationHandler                                                   */
/*!
    Set up an abnormal termination handler

    The SetupTerminationHandler function registers a termination handler
    function with the kernel in case of an abnormal termination of this
    process.

==============================================================================*/
static void SetupTerminationHandler( void )
{
    static struct sigaction sigact;

    memset( &sigact, 0, sizeof(sigact) );

    sigact.sa_sigaction = TerminationHandler;
    sigact.sa_flags = SA_SIGINFO;

    sigaction( SIGTERM, &sigact, NULL );

}

/*============================================================================*/
/*  TerminationHandler                                                        */
/*!
    Abnormal termination handler

    The TerminationHandler function will be invoked in case of an abnormal
    termination of this process.  The termination handler closes
    the connection with the variable server and cleans up its VARFP shared
    memory.

@param[in]
    signum
        The signal which caused the abnormal termination (unused)

@param[in]
    info
        pointer to a siginfo_t object (unused)

@param[in]
    ptr
        signal context information (ucontext_t) (unused)

==============================================================================*/
static void TerminationHandler( int signum, siginfo_t *info, void *ptr )
{
    /* signum, info, and ptr are unused */
    (void)signum;
    (void)info;
    (void)ptr;

    if ( VARSERVER_Close( state.hVarServer ) == EOK )
    {
        state.hVarServer = NULL;
    }

    if ( VARFP_Close( state.pVarFP ) == EOK )
    {
        state.pVarFP = NULL;
    }

    exit(1);
}

/*============================================================================*/
/*  SendVarsHeader                                                            */
/*!
    Send a variable query response header

    The SendVarsHeader function sends a variable response header

    @retval EOK response sent successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static void SendVarsHeader( void )
{
    /* output the response header */
    printf("Status: 200 OK\r\n");
    printf("Content-Type: application/json\r\n\r\n");

    /* output the response body */
    printf("{\"values\" : [");

}

/*============================================================================*/
/*  OutputJSONVar                                                             */
/*!
    Output a variable JSON object with a prefix

    The OutputJSONVar function prints a variable JSON object with a prefix.
    The prefix is intended to be either a space, or a comma so this
    function can be used to output a list of variables and prepend (or not)
    a comma.

    The object will be similar to the following:

    { "name" : "some name", "value" : "some value" }

    @param[in]
        info
            pointer to the variable information

    @param[in]
        value
            value of the variable as a string

    @retval EOK the JSON object was output
    @retval EINVAL invalid arguments

==============================================================================*/
static int OutputJSONVar( char prefix, VarInfo *info, char *value )
{
    int result = EINVAL;

    if ( ( info != NULL ) &&
         ( value != NULL ) )
    {
        if (IsJSON( value ) == true )
        {
            if ( info->instanceID == 0 )
            {
                printf( "%c{ \"name\": \"%s\", "
                        "\"value\" : %s }",
                        prefix,
                        info->name,
                        value );

            }
            else
            {
                printf( "%c{ \"name\": \"%s\", "
                        "\"instanceID\" : %d, "
                        "\"value\" : %s }",
                        prefix,
                        info->name,
                        info->instanceID,
                        value );
            }
        }
        else
        {
            if ( info->instanceID == 0 )
            {
                printf( "%c{ \"name\": \"%s\", "
                        "\"value\" : \"%s\" }",
                        prefix,
                        info->name,
                        value );
            }
            else
            {
                printf( "%c{ \"name\": \"%s\", "
                        "\"instanceID\" : %d, "
                        "\"value\" : \"%s\" }",
                        prefix,
                        info->name,
                        info->instanceID,
                        value );
            }
        }

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  SendVarsFooter                                                            */
/*!
    Send a variable query response footer

    The SendVarsFooter function sends a variable response footer

    @param[in]
        count
            count of the number of variables in the payload

==============================================================================*/
static void SendVarsFooter( int count )
{
    printf("],\"count\": %d }\n", count );
}

/*============================================================================*/
/*  ErrorResponse                                                             */
/*!
    Send an error response

    The ErrorResponse function sends an error response to the client
    using the Status header, and the status code and error description
    in a JSON object.

    @param[in]
        status
            status response code

    @param[in]
        description
            status response description

    @param[in]
        errorCode
            internal error code

    @retval EOK the response was sent
    @retval EINVAL invalid arguments

==============================================================================*/
static int ErrorResponse( int status,  char *description, uint32_t errorCode )
{
    int result = EINVAL;

    if ( description != NULL )
    {
        /* output header */
        printf("Status: %d %s\r\n", status, description);
        printf("Content-Type: application/json\r\n\r\n");

        /* output body */
        printf("{\"status\": %d, "
               "\"description\" : \"%s\", "
               "\"errorcode\" : \"0x%04X\"}",
                status,
                description,
                errorCode );

        result = EOK;

    }

    return result;
}

/*============================================================================*/
/*  IsJSON                                                                    */
/*!
    Determine if the string is a JSON object

    The IsJSON function examines the non-whitespace characters at the
    beginning and end of the value to determine if the value is likely
    a JSON object.  If the first and last non-whitespace characters are
    [ and ] or { and }, then the value is likely a JSON object

    @param[in]
        value
            value to be checked to see if it is JSON


    @retval true the value is likely a JSON object
    @retval false the value is not a JSON object

==============================================================================*/
static bool IsJSON( char *value )
{
    char c_start = ' ';
    char c_end = ' ';
    bool result = false;
    int i=0;
    int len;

    if ( value != NULL )
    {
        // get the length of the string
        len = strlen(value);
        if ( len > 0 )
        {
            // get the first non-space character at the
            // beginning of the value
            while(isspace(value[i]) && ( i < len))
            {
                i++;
            }

            if ( i < len )
            {
                c_start = value[i];
            }

            // search for the first non-whitespace character at the
            // end of the value
            i = len-1;
            while(isspace(value[i]) && ( i >= 0 ))
            {
                i--;
            }

            if ( i >= 0 )
            {
                c_end = value[i];
            }

            // check if we have a JSON object
            if ( ( c_start == '[' && c_end == ']' ) ||
                ( c_start == '{' && c_end == '}' ) )
            {
                // probably a JSON object since the start and end
                // characters of the value are '
                result = true;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  NewCache                                                                  */
/*!
    Create a new variable cache

    The NewCache function creates a new variable cache to be used to
    cache variable queries.

    If an error occurred, the return value will be NULL, otherwise the
    function will return a pointer to the new cache

    @param[in]
        name
            name of the variable cache

    @retval pointer to the requested variable cache
    @retval NULL if no variable cache could be created

==============================================================================*/
static CacheNode *NewCache( char *name )
{
    CacheNode *pNode = NULL;

    if ( name != NULL )
    {
        /* allocate memory for the cache node */
        pNode = calloc( 1, sizeof( CacheNode ) );
        if ( pNode != NULL )
        {
            /* set the cache name */
            pNode->pName = strdup(name);
            if ( pNode->pName != NULL )
            {
                /* initialize the cache */
                if( VARCACHE_Init( &pNode->pVarCache, 0, 0 ) != EOK )
                {
                    free( pNode->pName );
                    pNode->pName = NULL;
                    free( pNode );
                    pNode = NULL;
                }
            }
        }
    }

    return pNode;
}

/*============================================================================*/
/*  AddCache                                                                  */
/*!
    Add a new variable cache

    The AddCache function creates and adds a new variable cache
    to the FCGI server's cache list.

    If an error occurred, the return value will be NULL, otherwise the
    function will return a pointer to the new cache

    @param[in]
        pState
            pointer to the FCGIVars state object to contain the new
            variable cache

    @param[in]
        name
            name of the variable cache

    @retval pointer to the requested variable cache
    @retval NULL if no variable cache could be found or created

==============================================================================*/
static VarCache *AddCache( FCGIVarsState *pState, char *name )
{
    VarCache *pVarCache = NULL;
    CacheNode *pCacheNode;

    if ( ( pState != NULL ) && ( name != NULL ) )
    {
        pCacheNode = NewCache( name );
        if ( pCacheNode != NULL )
        {
            pVarCache = pCacheNode->pVarCache;

            if ( pState->pCacheList == NULL )
            {
                pState->pCacheList = pCacheNode;
            }
            else
            {
                pCacheNode->pNext = pState->pCacheList;
                pState->pCacheList = pCacheNode;
            }
        }
    }

    return pVarCache;
}

/*============================================================================*/
/*  FindCache                                                                 */
/*!
    Get a pointer to the specified variable cache

    The FindCache function gets a pointer to the specified variable cache.
    If no cache of the speciied name is found, the return value will be NULL

    @param[in]
        pState
            pointer to the FCGIVars state object containing the requested
            variable cache

    @param[in]
        name
            name of the variable cache

    @retval pointer to the requested variable cache
    @retval NULL if no variable cache could be found

==============================================================================*/
static VarCache *FindCache( FCGIVarsState *pState, char *name )
{
    VarCache *pVarCache = NULL;
    CacheNode *pCacheNode = NULL;

    if ( ( pState != NULL ) && ( name != NULL ) )
    {
        /* select the first cache node */
        pCacheNode = pState->pCacheList;

        /* iterate through the cache node list */
        while( pCacheNode != NULL )
        {
            /* check if the cache node name is set */
            if ( pCacheNode->pName != NULL )
            {
                /* check the cache node name for a match */
                if ( strcmp( pCacheNode->pName, name ) == 0 )
                {
                    /* match found */
                    pVarCache = pCacheNode->pVarCache;
                    break;
                }
            }

            /* select the next cache node */
            pCacheNode = pCacheNode->pNext;
        }
    }

    return pVarCache;
}

/*============================================================================*/
/*  GetCache                                                                  */
/*!
    Get a pointer to the specified variable cache

    The GetCache function gets a pointer to the specified variable cache.
    If no cache of the speciied name is found, one will be created.

    If an error occurred, the return value will be NULL.

    The cache may or may not have cache entries depending on its
    previous usage.

    @param[in]
        pState
            pointer to the FCGIVars state object containing the requested
            variable cache

    @param[in]
        name
            name of the variable cache

    @retval pointer to the requested variable cache
    @retval NULL if no variable cache could be found or created

==============================================================================*/
static VarCache *GetCache( FCGIVarsState *pState, char *name )
{
    VarCache *pVarCache = NULL;

    if ( ( pState != NULL ) && ( name != NULL ) )
    {
        pVarCache = FindCache( pState, name );
        if ( pVarCache == NULL )
        {
            pVarCache = AddCache( pState, name );
        }
    }

    return pVarCache;
}

/*! @>
 * end of fcgi_vars group */
