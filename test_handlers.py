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
    def setUp(self):
        """expects server on localhost:8000"""
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.autocommit = True
        self.db.executescript(''.join(schema.tabledef))
        self.keep_serving = True
        AppHandlers.UseDb(self.db)
        self.httpd = httpd = http.server.ThreadingHTTPServer(('', 8000), AppHandlers)
        self.t1 = threading.Thread(target=self.httpd.serve_forever)
        self.t1.start()
    def tearDown(self):
        self.keep_serving = False
        self.httpd.shutdown()
        self.t1.join()
        self.db.close()

    def post(self, path: str, data: dict):
        host = "127.0.0.1:8000"
        connection = http.client.HTTPConnection(host)
        headers = {'Content-type': 'application/json'}
        json_data = json.dumps(data)
        # connection.set_debuglevel(1)
        connection.request(method='POST', url=path, body=json_data, headers=headers)
        response = connection.getresponse().read()
        print(response)
        try:
            body = json.loads(response)
        except Exception:
            body= {"got": str(response)}
        finally:
            connection.close()
        return body
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
        path="/api/login"
        send={"email": "me@me", "password":"me"}
        return self.post(path, send)
    def admin_login(self):
        path="/api/login"
        send={"email":"admin@admin", "password":"me"}
        return self.post(path, send)
    def test_login(self):
        self.add_user({"email": "me@me", "password":"me"})
        path="/api/login"
        send={"email": "me@me", "password":"me"}
        want = {'message': 'logged in! ', 'success': 'true'}
        have = self.post(path, send)
        self.assertEqual(have, want)

        send={"email":"doesntexists@example.com", "password":"asdf"}
        want={'message': "couldn't login", 'success': 'false'}
        have = self.post(path, send)
        self.assertEqual(have, want)

        send={"email":"me@me", "password":"wrongpassword"}
        want={'message': "couldn't login", 'success': 'false'}
        have=self.post(path,send)
        self.assertEqual(have, want)

    def test_get_user(self):
        self.add_user()
        self.add_admin_user()
        self.user_login()

        path="/api/get_user"
        send={"uid": "1"}
        want=[{'uid': 1, 'email': 'me@me', 'name': '', 'role': 'user', 'password': ''}]
        have=self.post(path, send)
        self.assertEqual(have, want)

        path="/api/get_user"
        send={}
        want=[{'email': 'me@me', 'name': '', 'password': '', 'role': 'user', 'uid': 1},
              {'email': 'admin@admin', 'name': 'admin', 'password': '', 'role': 'admin','uid': 2}]
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
            poster=f.read().hex()
            path="/api/add_movie"
            send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}
            want={"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster}
            have=self.post(path, send)
            self.assertEqual(have, want)

            path="/api/get_movie"
            send={"mid": have['mid']}
            want=[{"mid": 1, "title": "Johnny Mnemonic", "length": l.total_seconds(), "poster":poster}]
            have=self.post(path, send)
            self.assertEqual(have, want)

    def test_theater(self):
        path="/api/add_theater"
        send={}
        want={"success": "false"}
        have=self.post(path, send)
        self.assertEqual(have['success'], want['success'])

        path="/api/add_theater"
        send={"name": "My Film Hall", "seats": 500}
        want={"tid": 1, "name": "My Film Hall", "seats": 500}
        have = self.post(path, send)
        self.assertEqual(have, want)

        path="/api/get_theater"
        send={"tid":1}
        want=[{"tid": 1, "name": "My Film Hall", "seats": 500}]
        have=self.post(path,send)
        self.assertEqual(have, want)

    def test_show(self):
        path="/api/add_show"
        send={}
        want={"success": "false"}
        have=self.post(path, send)
        self.assertEqual(have['success'], want['success'])

        path="/api/add_theater"
        send={"name": "My Film Hall", "seats": 500}
        theater = self.post(path, send)
        
        with open("jm.jpg", "rb") as f:
            l = datetime.timedelta(hours=1, minutes=36)
            poster=f.read().hex()
            path="/api/add_movie"
            send={"title": "Johnny Mnemonic", "length": l.total_seconds(), "poster": poster}
            movie=self.post(path, send)

            start = datetime.datetime.today()
            theater=self.post("/api/get_theater", {"tid": 1})[0]
            movie=self.post("/api/get_movie", {"mid":1})[0]
            print(theater)
            path="/api/add_show"
            send={'movie': movie, 'startTime': start.isoformat(), 'theater': theater, 'seats': 2}
            want={'sid': 1, 'movie': movie, 'startTime': start.isoformat(), 'theater': theater, 'seats': 2, 'max_seats': theater['seats']}
            have=self.post(path, send)
            have['movie'] = json.loads(have['movie'])
            have['theater'] = json.loads(have['theater'])
            self.assertEqual(have, want)

            path="/api/book_show"
            send={"sid": 1}
            want={'success': 'true'}
            have=self.post(path, send)
            self.assertEqual(have, want)
if __name__ == '__main__':
    unittest.main()
