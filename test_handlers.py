#!/bin/python3
import unittest
import schema
import sqlite3
import http.server
import http.client
import handlers
import json
import threading
import urllib.request
from handlers import AppHandlers
import datetime
class TestHandlers(unittest.TestCase):
    _token = None
    def setUp(self):
        """expects server on localhost:8000"""
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.autocommit = True
        self.db.executescript(''.join(schema.tabledef))
        self.keep_serving = True
        AppHandlers.UseDb(self.db)
        self.httpd = http.server.ThreadingHTTPServer(('', 8000), AppHandlers)
        self.t1 = threading.Thread(target=self.httpd.serve_forever)
        self.t1.start()

    def tearDown(self):
        self.keep_serving = False
        self.httpd.shutdown()
        self.t1.join()
        self.httpd.server_close()
        self.db.close()

    def post(self, path: str, data: dict):
        host = "127.0.0.1:8000"
        headers = {'Content-type': 'application/json'}
        if self._token:
            headers['Cookie'] = self._token
        json_data = json.dumps(data).encode()
        connection = http.client.HTTPConnection(host)
        # connection.set_debuglevel(1)
        connection.request(method='POST', url=path, body=json_data, headers=headers)
        r = connection.getresponse()
        ck = r.getheader('Set-Cookie')
        if ck is not None:
            self._token = ck
        response = r.read()
        try:
            ret = json.loads(response)
        except Exception as e:
            ret = {"got": str(e)}
        return ret

    def get(self, path: str):
        host = "127.0.0.1:8000"
        headers = {'Content-type': '*'}
        if self._token:
            headers['Cookie'] = self._token
        connection = http.client.HTTPConnection(host)
        # connection.set_debuglevel(1)
        connection.request(method='GET', url=path, headers=headers)
        r = connection.getresponse()
        ck = r.getheader('Set-Cookie')
        if ck is not None:
            self._token = ck
        return r.read()

    def logout(self):
        self._token = None

    def add_user(self, d:dict = {"email":"me@me", "password":"me"}):
        return self.post("/api/add_user", d)

    def add_admin_user(self):
        d:dict = {"email":"admin@admin", "password":"admin", "name":"admin"}
        u = schema.add_user(self.db, schema.User(email=d['email'],
                                             name=d['name'],
                                             password=d['password'],
                                             role=schema.Role.ADMIN))
        return json.dumps(u.encode())
    def test_add_user(self):
        path = "/api/add_user"
        send = {"email":"me@me", "password":"me"}
        want = {'uid': 1, 'email': 'me@me', 'name': '', 'role': 'user', 'password': ''}
        have = self.post(path, send)
        self.assertEqual(have, want)

        want = {'message': 'UNIQUE constraint failed: users.email', 'success': 'false'}
        have = self.post(path, send)
        self.assertEqual(have, want)

    def user_login(self):
        self.logout()
        self.add_user()
        path="/api/login"
        send={"email": "me@me", "password":"me"}
        return self.post(path, send)
    def admin_login(self):
        self.logout()
        self.add_admin_user()
        path="/api/login"
        send={"email":"admin@admin", "password":"admin"}
        return self.post(path, send)
    def test_login(self):
        self.add_user({"email": "me@me", "password":"me"})
        # @@ doc @@
        path="/api/login"
        send={"email": "me@me", "password":"me"}
        want = {'email': 'me@me', 'name': '', 'password': '', 'role': 'user', 'uid': 1}
        # @@ doc_end @@
        have = self.post(path, send)
        self.assertEqual(have, want)
        # @@ doc @@
        path="/api/login"
        send={"email":"doesntexists@example.com", "password":"asdf"}
        want={'message': "couldn't login", 'success': 'false'}
        # @@ doc_end @@
        have = self.post(path, send)
        self.assertEqual(have, want)

        send={"email":"me@me", "password":"wrongpassword"}
        want={'message': "couldn't login", 'success': 'false'}
        have=self.post(path,send)
        self.assertEqual(have, want)

    def test_get_user(self):
        self.user_login()
        # @@ doc @@
        path="/api/get_user"
        send={"uid": "1"}
        want={"success": "false"} # normal user
        # @@ doc_end @@
        have=self.post(path, send)
        self.assertTrue(isinstance(have, dict))
        self.assertEqual(have['success'], want['success'])

        self.logout()
        # @@ doc @@
        self.admin_login()
        path="/api/get_user"
        send={}
        want=[{'email': 'me@me', 'name': '', 'password': '', 'role': 'user', 'uid': 1},
              {'email': 'admin@admin', 'name': 'admin', 'password': '', 'role': 'admin','uid': 2}]
        # @@ doc_end @@
        have=self.post(path, send)
        self.assertEqual(have, want)

    def test_movie(self):
        path="/api/add_movie"
        send={}
        want={"success": "false"}
        have=self.post(path, send)
        self.assertEqual(have['success'], want['success'])

        with open("jm.jpg", "rb") as f:
            l = datetime.timedelta(hours=1, minutes=36)
            poster_bytes=f.read()
            poster_hex=poster_bytes.hex()

            # @@ doc @@
            path="/api/add_movie"
            send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster_hex}
            want={'success': 'false', 'message': 'login required'}
            # @@ doc_end @@
            have=self.post(path, send)
            self.assertEqual(have, want)

            # @@ doc @@
            self.user_login()
            path="/api/add_movie"
            send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster_hex}
            want={'success': 'false', 'message': 'only admin'}
            # @@ doc_end @@
            have=self.post(path, send)
            self.assertEqual(have, want)

            # @@ doc @@
            self.admin_login()
            path="/api/add_movie"
            send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster_hex}
            want={"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster_hex}
            # @@ doc_end @@
            have=self.post(path, send)
            self.assertEqual(have, want)

            # @@ doc @@
            self.user_login()
            path="/api/get_movie"
            send={"mid": have['mid'], "full":True}
            want=[{"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster_hex}]
            # @@ doc_end @@
            have=self.post(path, send)
            self.assertEqual(have, want)

            # @@ doc @@
            self.user_login()
            path="/api/get_movie"
            send={"mid": have[0]['mid'], "full":False}
            have=self.post(path, send)
            for movie in have:
                movie['poster'] = self.get(f"/api/get_movie_poster?mid={movie['mid']}")
            want=[{"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster_bytes}]
            self.assertEqual(have, want)
            # @@ doc_end @@

    def test_theater(self):
        path="/api/add_theater"
        send={}
        want={"success": "false"}
        have=self.post(path, send)
        self.assertEqual(have['success'], want['success'])

        # @@ doc @@
        self.admin_login()
        path="/api/add_theater"
        send={"name": "My Film Hall", "seats": 500}
        want={"tid": 1, "name": "My Film Hall", "seats": 500}
        # @@ doc_end @@
        have = self.post(path, send)
        self.assertEqual(have, want)

        # @@ doc @@
        self.user_login()
        path="/api/get_theater"
        send={"tid":1}
        want=[{"tid": 1, "name": "My Film Hall", "seats": 500}]
        # @@ doc_end @@
        have=self.post(path,send)
        self.assertEqual(have, want)

        # @@ doc @@
        path="/api/add_theater"
        send={"name": "My Film Hall 2", "seats": 10}
        want={'success': 'false', 'message': 'only admin'}
        # @@ doc_end @@
        have = self.post(path, send)
        self.assertEqual(have, want)

    def test_show(self):
        self.admin_login()
        path="/api/add_show"
        send={}
        want={"success": "false"}
        have=self.post(path, send)
        self.assertEqual(have['success'], want['success'])

        path="/api/add_theater"
        send={"name": "My Film Hall", "seats": 500}
        theater = self.post(path, send)
        
        with open("jm.jpg", "rb") as f:
            # @@ doc @@
            l = datetime.timedelta(hours=1, minutes=36)
            poster=f.read().hex()
            path="/api/add_movie"
            send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}
            # @@ doc_end @@
            movie=self.post(path, send)

            start = datetime.datetime.today()
            theater=self.post("/api/get_theater", {"tid": 1})[0]
            movie=self.post("/api/get_movie", {"mid":1})[0]

            # @@ doc @@
            path="/api/add_show"
            send={'movie': movie, 'startTime': start.isoformat(), 'theater': theater, 'seats': 2}
            want={'sid': 1, 'movie': movie, 'startTime': start.isoformat(), 'theater': theater, 'seats': 2, 'max_seats': theater['seats']}
            # @@ doc_end @@
            have=self.post(path, send)
            have['movie'] = json.loads(have['movie'])
            have['theater'] = json.loads(have['theater'])
            self.assertEqual(have, want)

            # @@ doc @@
            self.user_login()
            path="/api/book_show"
            send={"sid": 1}
            want={'success': 'true'}
            # @@ doc_end @@
            have=self.post(path, send)
            self.assertEqual(have, want)
if __name__ == '__main__':
    unittest.main()
