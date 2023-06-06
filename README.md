# fcgi_vars
FCGI VarServer Interface

## Overview

The fcgi_vars service is a FastCGI server which interfaces with the
VarServer to perform VarServer queries via GET and POST HTTP requests.
The fcgi_vars service currently supports the following features:

- query variables by their names with multiple variables per request
- query variables by a partial match of their name
- set variables by their names with multiple variables per request
- create custom variable groupings via the caching mechanism
- perform queries via GET requests
- perform queries via POST requests

## Build

The build script installs build tools and the lighttpd web server via apt-get.
It then compiles and installs the FCGI library before finally compiling
and installing the fcgi_vars service.

The fcgi_vars service is automatically invoked by the lighttpd web server when
the lighttpd web server starts.

```
./build.sh
```

## Prerequisites

The fcgi_vars service requires the following components:

- varserver : variable server ( https://github.com/tjmonk/varserver )
- FCGI : Fast CGI ( https://github.com/FastCGI-Archives/fcgi2 )

The example is run using the lighttpd web server ( https://www.lighttpd.net/).

The build script installs the lighttpd web server, and builds the FCGI library.

## Set up the VarServer

```
varserver &

mkvar -t uint16 -n /sys/test/a
mkvar -t uint32 -n /sys/test/b
mkvar -t float -n /sys/test/f
mkvar -t str -n /sys/test/c

setvar /sys/test/a 10
setvar /sys/test/b 9
setvar /sys/test/f 3.1415
setvar /sys/test/c "Hello World"

```

## Start the lighttpd server

```
lighttpd -f test/lighttpd.conf
```

## Sample Lighttpd Configuration

```
server.modules = (
    "mod_auth",
    "mod_cgi",
    "mod_fastcgi",
    "mod_setenv"
)

server.document-root        = "/www/pages"
server.upload-dirs          = ( "/var/cache/lighttpd/uploads" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/var/run/lighttpd.pid"
#server.username             = "www-data"
#server.groupname            = "www-data"
server.port                 = 80

setenv.add-response-header = ("Access-Control-Allow-Origin" => "*" )

index-file.names            = ( "index.php", "index.html", "index.lighttpd.html" )
url.access-deny             = ( "~", ".inc" )
static-file.exclude-extensions = ( ".php", ".pl", ".fcgi" )

compress.cache-dir          = "/var/cache/lighttpd/compress/"
compress.filetype           = ( "application/javascript", "text/css", "text/html", "text/plain" )

fastcgi.debug = 1
fastcgi.server = (
  "/vars" => ((
    "bin-environment" => (
        "LD_LIBRARY_PATH" => "/usr/local/lib"
    ),
    "bin-path" => "/usr/local/bin/fcgi_vars",
    "socket" => "/tmp/fcgi_vars.sock",
    "check-local" => "disable",
    "max-procs" => 1,
  ))
)
```

## Perform VarServer name query

```
curl localhost/vars?name=/sys/test/a,/sys/test/b
```
```
{"values" : [ { "name": "/sys/test/a", "value" : "10" },{ "name": "/sys/test/b", "value" : "9" }],"count": 2 }
```

## Perform VarServer match query

```
curl localhost/vars?match=/test/
```
```
{"values" : [ { "name": "/sys/test/a", "value" : "10" },{ "name": "/sys/test/b", "value" : "9" },{ "name": "/sys/test/f", "value" : "3.141500" },{ "name": "/sys/test/c", "value" : "Hello World" }],"count": 4 }
```

## Perform VarServer Set request

```
curl localhost/vars?set=/sys/test/a=12,/sys/test/b=15
```
```
{"values" : [ { "name": "/sys/test/a", "value" : "12" },{ "name": "/sys/test/b", "value" : "15" }],"count": 2 }
```

## Perform Cached Queries

We can cache a query and give it a name for faster subsequent access.  Only the
variable handles are cached, not the values.  Caching gives us a flexible way
to build

```
curl localhost/vars?name=/sys/test/a,/sys/test/b\&cache=ints
{"values" : [ { "name": "/sys/test/a", "value" : "12" },{ "name": "/sys/test/b", "value" : "15" }],"count": 2 }
```

Then we can query just using the cache name

```
curl localhost/vars?cache=ints
```

```
{"values" : [ { "name": "/sys/test/a", "value" : "12" },{ "name": "/sys/test/b", "value" : "15" }],"count": 2 }
```

Then we can change the values and confirm the cache still works

```
setvar /sys/test/a 1
setvar /sys/test/b 2
curl localhost/vars?cache=ints
```
```
{"values" : [ { "name": "/sys/test/a", "value" : "1" },{ "name": "/sys/test/b", "value" : "2" }],"count": 2 }
```

Then we can clear the cache

```
curl localhost/vars?clearcache=ints
```
```
{"values" : [],"count": 0 }
```

And confirm the cache is empty

```
curl localhost/vars?cache=ints
```

```
{"values" : [],"count": 0 }
```

## GET vs POST requests

For ease of illustration, all of the queries shown so far as using GET requests.
In the case of the POST request, the URL is the same, but the POST body contains
all of the query string after the '?' in the GET requests.

Here is an example of a POST vars name query request:

```
curl -X POST localhost/vars -d "name=/sys/test/a,/sys/test/b"
```

```
{"values" : [ { "name": "/sys/test/a", "value" : "1" },{ "name": "/sys/test/b", "value" : "2" }],"count": 2 }
```
