#!/bin/python3
import unittest
import schema
import sqlite3
from datetime import timedelta, datetime
from typing import Tuple

class TestDB(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.autocommit = True
        self.db.executescript(''.join(schema.tabledef))
        #self.db.set_trace_callback(print)
    def tearDown(self):
        self.db.close()

    def test_user(self):
        orig, ret = self.add_user()
        
        self.assertListEqual([ret.email, ret.name], [orig.email, orig.name])
        
        u = schema.get_user(self.db, uid=ret.uid)[0]
        self.assertNotEqual(u.password, orig.password)
        self.assertNotEqual(ret.password, orig.password)

    def test_login(self):
        orig, ret = self.add_user()
        self.assertTrue(schema.login(self.db, orig.email, orig.password))
        
        # return value should remove password
        self.assertFalse(schema.login(self.db, orig.email, ret.password))
        u = schema.get_user(self.db, uid=ret.uid)[0]
        self.assertFalse(schema.login(self.db, u.email, u.password))

    def add_user(self, uid: int = 10) -> Tuple[schema.User, schema.User]:
        "Helper to add users"
        orig = schema.User("me@me",
                    "me",
                    role=schema.Role.ADMIN,
                    password="me",
                    uid=uid)
        ret = schema.add_user(self.db, orig)
        return orig, ret

    def add_movie(self, title: str = "Test Movie", length: timedelta = timedelta(hours=3), poster: bytes = b''):
        return schema.add_movie(self.db, title, length, poster)
    def get_movies(self, **kwargs) -> list[schema.Movie]:
        return schema.get_movie(self.db, **kwargs)

    def test_movie(self):
        m1 = self.add_movie("12 Angry Men", timedelta(hours=3))
        m2 = self.add_movie("My Dinner with Andrei", timedelta(hours=3))
        o = self.get_movies()
        # assumption: insertion order is preserved.
        return self.assertListEqual([m1, m2], o)

    def add_theater(self, name: str = "Test theater", seats: int = 10) -> schema.Theater:
        return schema.add_theater(self.db, name, seats)

    def test_theater(self):
        t1 = self.add_theater("Theater1")
        t2 = self.add_theater("Theater2", 15)
        o = schema.get_theater(self.db)
        # assumption: insertion order is preserved
        return self.assertListEqual([t1, t2], o)

    def test_show(self):
        m1 = self.add_movie()
        t1 = self.add_theater()
        s1 = schema.Show(m1, datetime.today(), t1)
        schema.add_show(self.db, s1)
        s2 = schema.Show(m1, datetime.today(), t1)
        schema.add_show(self.db, s2)
        
        o = schema.get_show(self.db)
        self.assertListEqual([s1, s2], o)

        schema.book_show(self.db, s1.sid)
        s1.seats = s1.seats+1
        o = schema.get_show(self.db, sid=s1.sid)[0]
        self.assertEqual(s1.seats, o.seats)


if __name__ == '__main__':
    unittest.main()
