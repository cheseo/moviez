#!/bin/python3
import argparse
import urllib.parse as urlparse
import server
import sqlite3
import http.server
import schema
from typing import Callable, Any
import datetime

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AppHandlers(server.Handler):
    db: sqlite3.Connection

    @classmethod
    def UseDb(cls, db: sqlite3.Connection) -> None:
        cls.db = db

    @staticmethod
    def admin_only(f: Callable):
        """Decorator for ensuring only admins have accesss to path. Doesn't work yet."""
        def wrapper(*args, **kwargs):
            self = args[0]
            if not self.is_logged_in():
                self.redirect_login()
                return
            if self.user.role != 'ADMIN':
                self.send_response(http.HTTPStatus.FORBIDDEN, "Ony admins can access this api")
                return
            return f(*args, **kwargs)
        return wrapper

    def is_logged_in(self) -> bool:
        token = self.Headers['Token'] or None
        if token is None:
            return False
        return True

    def send_json(self, msg: Any):
        """Schema objects all have .encode() and .decode() to convert to/from json."""
        self.send_message(msg.encode().encode())
        
    def send_json_list(self, lst: list):
        """Assumes the items inside list is always from Schema module"""
        o = []
        for itm in lst:
            o.append(itm.encode())
        b = '[' + ','.join(o) +']'
        self.send_message(b.encode())

    def filters_from_body(self, want: set) -> tuple[Any,bool]:
        """remove unwanted keys from the dictionary of body"""
        bk = self.body.keys()
        extra = bk - want
        if len(extra) > 0:
            self.send_error_json(f"extra elements: {extra!r}")
            return None, False
        return self.body, True

    @server.Handler.route("/")
    def index(self):
        self.send_response(http.HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(b"Hello from python! Pease use the /api/ routes for the JSON api.")

    @server.Handler.route("/api/login")
    def get_login(self):
        self.send_error(http.HTTPStatus.METHOD_NOT_ALLOWED, 'please POST the json to /api/login')

    @server.Handler.route("/api/login", "POST")
    def post_login(self):
        want = {'email', 'password'}
        filters, ok = self.filters_from_body({'email', 'password'})
        if not ok:
            return
        u = schema.User.decode(filters)
        u.uid = schema.login(self.db, u.email, u.password)
        if not u.uid:
            self.send_error_json("couldn't login")
            return
        u = schema.get_user(self.db, uid=u.uid)[0]
        self.send_json(u)

    @server.Handler.route("/api/add_user", "POST")
    def add_user(self):
        want = {'email', 'password', 'name'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        user = schema.User.decode(filters)
        try:
            u2 = schema.add_user(self.db, user)
        except sqlite3.IntegrityError as e:
            self.send_error_json(str(e))
            return
        self.send_json(u2)

    @admin_only
    @server.Handler.route("/api/get_user", "POST")
    def get_user(self):
        want = {'email', 'uid', 'name'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        self.body
        users = schema.get_user(self.db, **filters)
        self.send_json_list(users)

    @server.Handler.route("/api/get_movie", "POST")
    def get_movie(self):
        want = {'mid', 'title', 'poster'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        movies = schema.get_movie(self.db, **filters)
        self.send_json_list(movies)

    @admin_only
    @server.Handler.route("/api/add_movie", "POST")
    def add_movie(self):
        want = {'title', 'length', 'poster'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        try:
            filters['title'] = self.body['title']
            filters['length'] = datetime.timedelta(seconds=self.body['length'])
        except KeyError as e:
            self.send_error_json("add movie, required title and length;" + str(e))
            return

        if 'poster' in self.body:
            filters['poster'] = bytes.fromhex(self.body['poster'])
        movie = schema.add_movie(self.db, **filters)
        self.send_json(movie)

    @server.Handler.route("/api/get_theater", "POST")
    def get_theater(self):
        want = {'name', 'seats', 'tid'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        theaters = schema.get_theater(self.db, **filters)
        self.send_json_list(theaters)

    @admin_only
    @server.Handler.route("/api/add_theater", "POST")
    def add_theater(self):
        want = {'name', 'seats', 'tid'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        if 'tid' in filters:
            # let us chose the tid
            del filters['tid']
        self.send_json(schema.add_theater(self.db, **filters))

    @server.Handler.route("/api/get_show", "POST")
    def get_show(self):
        want = {'movie', 'startTime', 'theater', 'seats', 'max_seats', 'sid'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        self.send_json_list(schema.get_show(self.db, **filters))

    @admin_only
    @server.Handler.route("/api/add_show", "POST")
    def add_show(self):
        want = {'movie', 'startTime', 'theater', 'seats', 'max_seats', 'sid'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        try:
            filters['movie'] = schema.Movie.decode(filters['movie'])
            filters['startTime'] = datetime.datetime.fromisoformat(filters['startTime'])
            filters['theater'] = schema.Theater.decode(filters['theater'])
            s = schema.Show(**filters)
        except Exception as e:
            self.send_error_json("creating show: " + str(e))
            return
        try:
            show = schema.add_show(self.db,s)
        except Exception as e:
            self.send_error_json("sechema.add_show: " + str(e))
            return
        self.send_json(show)

    @server.Handler.route("/api/book_show", "POST")
    def book_show(self):
        want = {'sid', 'count'}
        filters, ok = self.filters_from_body(want)
        if not ok:
            return
        if 'sid' not in self.body:
            self.send_error_json("book_show: sid needed")
            return
        if 'count' not in self.body:
            self.body['count'] = 1
        if self.body['count'] < 1:
            self.send_error_json("book_show: count must be positive")
            return
        try:
            schema.book_show(self.db, **self.body)
        except Exception as e:
            self.send_error_json("book_show: " + str(e), status=http.HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_message(b'{"success": "true"}')


def run(handlerClass, address: tuple[str, int] = ('', 8000)):
    httpd = http.server.ThreadingHTTPServer(address, handlerClass)
    logger.info(f"starting server at {address[0]}:{address[1]}")
    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="server.py",
                                     description="Serve movie browser api")
    parser.add_argument("-d", "--db", default="db.db")
    parser.add_argument("-H", "--hostname", default='')
    parser.add_argument("-p", "--port", default=8000, type=int)
    args = parser.parse_args()        
    con = sqlite3.connect(args.db, check_same_thread=False)
    con.execute("PRAGMA foreign_keys = 'on';")
    if args.db == ":memory:":
        con.executescript(''.join(schema.tabledef))
    AppHandlers.UseDb(con)
    try:
        run(AppHandlers, (args.hostname, args.port))
    finally:
        con.close()

        
