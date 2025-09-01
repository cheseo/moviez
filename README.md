A Theater/Show/Movie database in python.
It uses 0 external dependency!

# Usage
For first run, you have to use:
```bash
$ make
OR
$ ./createTables
$ ./handlers.py
```
The makefile does the two steps above.

To test, you can do:
```bash
$ make test
OR
$ python3 -m unittest
```

To use in-memory database, use:
`$ ./handlers.py -d ":memory:"`
This exploits the fact that sqlite's connect string uses :memory: for in-memory db. Anything passed as db is passed straight to sqlite's connection string.

handlers.py can be given different database, host and port as:
```
$ ./handlers.py -h
usage: server.py [-h] [-d DB] [-H HOSTNAME] [-p PORT]

Serve movie browser api

options:
  -h, --help            show this help message and exit
  -d, --db DB
  -H, --hostname HOSTNAME
  -p, --port PORT
```
# Structure
The main structures are:

- schema.py, test_db.py
  This is the database schema, methods to add to database,
  and the python classes the tables are abstracted as.

- server.py
  This is a helper module for writing http handlers. It exports
  @Handler.route("/path/to/resource", method="GET|POST")
  which is inspired by flask.

  It also has other common functionality, see pydoc[1]

- handlers.py, test_handlers.py
  This contains the actual handlers. see [2] for the api exported, and [3] for examples of api usage.
  The get* methods accept many arguments as filters. They are AND'ed together
  and the list of items that match the query are returned.

  Thus, to get all the users, one has to do:
  $ curl --json '{}' localhost:8000/api/get_user

  While to get all users of name 'John', (note it has to match 'John' literally)
  $ curl --json '{"name": "Jhon"}' localhost:8000/api/get_user
  
  The poster is sent as hex-encoded binary data. The format of the data is not specified,
  it has to be readble by the client.

  See the file test_handlers.py for other usages.


[1]:
```
  $ pydoc server.Handler

    server.Handler = class Handler(http.server.BaseHTTPRequestHandler)
   |  server.Handler(request, client_address, server)
   |
   |  flask-inspired handler class.
   |
   |  sets up headers, body and url parameters before calling respective route methods.
   |
   |  functions:
   |  - @route("/login", method="POST")
   |  - send_error_json(msg)
   |      redirect with HTTPStatus.BAD_REQUEST, setting the msg.
   |  - redirect(locatoin, status=HTTPStatus.TEMPORARY_REDIRECTw)
   |      doesn't send json, relies on HTTP.
   |      It calls end_headers() at the end.
   |  - sendfile(path):
   |      sends ./path file to the write pipe
   |  - send_error_json(msg: str, status: int = http.HTTPStatus.BAD_REQUEST)
   |  - send_json_ok(self, msg: str, status: http.HTTPStatus = http.HTTPStatus.OK)
   |  - send_message(self, message: bytes, status: int = http.HTTPStatus.OK)
   |  - redirect(self, location: str, status: int = http.HTTPStatus.TEMPORARY_REDIRECT)
   |
   |  It stores common variables like:
   |  - Headers: dict[str, str]
   |  - Url: urlparse.ParseResult
   |  - body: Any # Usually dict or list, converted from json
   |
   |  as instance variables.
```
[2]:
```
  $ grep --group-separator '' -A2 '@server.Handler.route' handlers.py 
```

[3]:
```
$ awk '/.* # @@ doc @@/,/.* # @@ doc_end @@/' test_handlers.py | sed 's,^[[:space:]]*,,g; s,.*@@.*,,g'

path="/api/login"
send={"email": "me@me", "password":"me"}
want = {'email': 'me@me', 'name': '', 'password': '', 'role': 'user', 'uid': 1}


path="/api/login"
send={"email":"doesntexists@example.com", "password":"asdf"}
want={'message': "couldn't login", 'success': 'false'}


path="/api/get_user"
send={"uid": "1"}
want={"success": "false"} # normal user


self.admin_login()
path="/api/get_user"
send={}
want=[{'email': 'me@me', 'name': '', 'password': '', 'role': 'user', 'uid': 1},
{'email': 'admin@admin', 'name': 'admin', 'password': '', 'role': 'admin','uid': 2}]


path="/api/add_movie"
send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}
want={'success': 'false', 'message': 'login required'}


self.user_login()
path="/api/add_movie"
send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}
want={'success': 'false', 'message': 'only admin'}


self.admin_login()
path="/api/add_movie"
send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}
want={"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster}


self.user_login()
path="/api/get_movie"
send={"mid": have['mid']}
want=[{"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster}]


self.admin_login()
path="/api/add_theater"
send={"name": "My Film Hall", "seats": 500}
want={"tid": 1, "name": "My Film Hall", "seats": 500}


self.user_login()
path="/api/get_theater"
send={"tid":1}
want=[{"tid": 1, "name": "My Film Hall", "seats": 500}]


path="/api/add_theater"
send={"name": "My Film Hall 2", "seats": 10}
want={'success': 'false', 'message': 'only admin'}


l = datetime.timedelta(hours=1, minutes=36)
poster=f.read().hex()
path="/api/add_movie"
send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}


path="/api/add_show"
send={'movie': movie, 'startTime': start.isoformat(), 'theater': theater, 'seats': 2}
want={'sid': 1, 'movie': movie, 'startTime': start.isoformat(), 'theater': theater, 'seats': 2, 'max_seats': theater['seats']}


self.user_login()
path="/api/book_show"
send={"sid": 1}
want={'success': 'true'}
```
