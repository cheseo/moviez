#!/bin/python3
from dataclasses import dataclass
from enum import StrEnum
import sqlite3
from datetime import timedelta, datetime
from collections import OrderedDict
from copy import copy
import json
from hashlib import sha256

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def select(con: sqlite3.Connection, query: str, Filter: dict = {}, cls = None) -> sqlite3.Cursor:
    query += " where 1 = 1 "
    for key in Filter.keys():
        if cls is not None and not hasattr(cls, key):
            raise ValueError(f"{key!r} is not in {cls} class")
        query += "and " + key + " = ? "
    query += ";"
    res = con.execute(query, list(Filter.values()))
    return res

def generic_decode(obj, my: set, d: dict): # TODO: using `-> User' errors out; figure out why.
        their = set(d.keys())
        # remove any extra keys
        got = their & my
        extra = their - my
        if len(extra) > 0:
            logger.info(f"got extra keys {extra}")
        for attr in got:
            obj.__setattr__(attr, d[attr])
        return obj

tabledef = []

class Role(StrEnum):
    ADMIN = 'admin'
    USER  = 'user'

@dataclass
class User:
    email: str
    name: str = ""
    role: Role = Role.USER
    password: str = ""
    uid: int = 0
    def __post_init__(self):
        if self.role not in Role:
            raise ValueError(f"role must be among {Role}")
        if isinstance(self.role, Role):
            self.role = self.role.value
    @classmethod
    def decode(cls, d: dict): # TODO: using `-> User' errors out; figure out why.
        u = User("")
        my = {'email', 'name', 'role', 'password', 'uid' }
        ret = generic_decode(u, my, d)
        ret.__post_init__()
        return ret
    def encode(self) -> str:
        me = {"uid": self.uid,
              "email": self.email,
              "name": self.name,
              "role": self.role,
              "password": self.password,
              }
        return json.dumps(me)

UserTable = """
create table users(uid integer primary key,
name text,
email text unique,
password text,
role text
);
"""
tabledef.append(UserTable)

def add_user(con: sqlite3.Connection, user: User) -> User:
    u = copy(user)
    u.uid = 0
    
    if u.role not in Role:
        raise ValueError(f"role must be among {Role}")
    q = """
    insert into users(name, email, password, role) values(?, ?, ?, ?) returning uid;
    """
    hashed = sha256(u.password.encode()).hexdigest()
    res = con.execute(q, (u.name, u.email, hashed, u.role)).fetchone()
    u.uid, u.password = res[0], ""
    return u

def get_user(con: sqlite3.Connection, **Filter) -> list[User]:
    q = "select uid, name, email, role from users"
    out = []
    for (uid, name, email, role) in select(con, q, Filter):
        out.append(User(uid = uid, name = name, email = email, role = role))
    return out

def login(con: sqlite3.Connection, email: str, pw: str) -> int:
    """
    Login and return the uid if found, 0 otherwise
    """
    q = """
    select uid from users where email = ? and password = ?;
    """
    hashed = sha256(pw.encode()).hexdigest()
    res = con.execute(q, (email, hashed))
    val = res.fetchone()
    if val is not None:
        return val[0]
    return 0


@dataclass
class Movie:
    mid: int
    title: str
    length: timedelta
    poster: bytes = b""

    # def __eq__(self, other) -> bool:
    #     s = [self.mid,  self.title,  self.length,  self.poster ]
    #     t = [other.mid, other.title, other.length, other.poster]
    #     return s == t
    @staticmethod
    def dummy():
        return Movie(0, '', timedelta())
    @classmethod
    def decode(cls, d: dict): # TODO: using `-> User' errors out; figure out why.
        m = Movie(0,"",timedelta(0))
        my = {'mid', 'title', 'length', 'poster'}
        ret = generic_decode(m, my, d)
        ret.length = timedelta(seconds=ret.length)
        ret.poster = bytes.fromhex(ret.poster)
        return ret
    def encode(self) -> str:
        me = {"mid": self.mid,
              "title": self.title,
              "length": self.length.total_seconds(),
              "poster": self.poster.hex(),
              }
        return json.dumps(me)
MovieTable = """
create table movie(mid integer primary key,
title text not null,
seconds text not null,
poster blob not null default ''
);
"""
tabledef.append(MovieTable)

def get_movie(con: sqlite3.Connection, **Filter) -> list[Movie]:
    q = "select mid, title, seconds from movie"
    movies = []
    for (mid, title, seconds) in select(con, q, Filter, Movie.dummy()):
        mm = Movie(mid = mid, title = title, length = timedelta(seconds=float(seconds)))
        with con.blobopen("movie", "poster", mid, readonly=True) as b:
            mm.poster = b.read()
        movies.append(mm)
    return movies

def add_movie(con: sqlite3.Connection, title: str, length: timedelta, poster: bytes = b'') -> Movie:
    if poster is not None:
        q = "insert into movie(title, seconds, poster) values(?, ?, ?) returning mid;"
        res = con.execute(q, (title, length.total_seconds(), poster))
    else:
        q = "insert into movie(title, seconds) values(?, ?) returning mid;"
        res = con.execute(q, (title, length.total_seconds()))
    # res = con.execute(q, (title, length.total_seconds(), poster))
    mid = res.fetchone()[0]
    m = Movie(mid = mid, title = title, length = length, poster = poster)
    return m

@dataclass
class Theater:
    name: str
    seats: int
    tid: int = 0
    @classmethod
    def decode(cls, d: dict): # TODO: using `-> User' errors out; figure out why.
        m = Theater("",0)
        my = {'name', 'seats', 'tid'}
        ret = generic_decode(m, my, d)
        return ret
    def encode(self) -> str:
        me = {"name": self.name,
              "seats": self.seats,
              "tid": self.tid,
              }
        return json.dumps(me)
TheaterTable = """
create table theater(tid integer primary key,
name text unique,
seats integer not null
);
"""
tabledef.append(TheaterTable)
def get_theater(con: sqlite3.Connection, **Filter) -> list[Theater]:
    q = "select tid, name, seats from theater"
    out = []
    for (tid, name, seats) in select(con, q, Filter, Theater):
        tt = Theater(name = name, tid = tid, seats = seats)
        out.append(tt)
    return out

def add_theater(con: sqlite3.Connection, name: str, seats: int) -> Theater:
    q = "insert into theater(name, seats) values(?, ?) returning tid;"
    res = con.execute(q, (name, seats))
    return Theater(tid = res.fetchone()[0], name = name, seats = seats)


@dataclass
class Show:
    movie: Movie
    startTime: datetime
    theater: Theater
    seats: int = 0
    max_seats: int = -1
    sid: int = 0

    @classmethod
    def decode(cls, d: dict): # TODO: using `-> User' errors out; figure out why.
        m = Show(Movie(0, "", timedelta(0)), datetime.fromtimestamp(0), Theater("", 0))
        my = {'movie', 'startTime', 'theater', 'seats', 'max_seats', 'sid'}
        ret = generic_decode(m, my, d)
        ret.movie = Movie.decode(json.loads(ret.movie))
        ret.startTime = datetime.fromisoformat(ret.startTime)
        ret.theater = Theater.decode(json.loads(ret.theater))
        ret.max_seats = ret.theater.seats
        return ret
    def encode(self) -> str:
        me = {"sid": self.sid,
              "movie": self.movie.encode(),
              "startTime": self.startTime.isoformat(),
              "theater": self.theater.encode(),
              "seats": self.seats,
              "max_seats": self.max_seats,
              }
        return json.dumps(me)
ShowTable = """
create table show(sid integer primary key,
date text not null,
mid integer not null,
tid integer,
seats integer default 0,
max_seats integer not null,
foreign key (mid) references movie(mid) on delete cascade,
foreign key (tid) references theater(tid) on delete cascade,
unique (date, tid));
"""
tabledef.append(ShowTable)

def get_show(con: sqlite3.Connection, **Filter) -> list[Show]:
    q = "select sid, date, mid, tid, seats, max_seats from show"
    res = select(con, q, Filter, Show)
    out = []
    for (sid, date, mid, tid, seats, ms) in res:
        s = Show(movie = get_movie(con, mid=mid)[0],
                 startTime = datetime.fromisoformat(date),
                 sid = sid,
                 theater = get_theater(con, tid=tid)[0],
                 seats = seats,
                 max_seats = ms)
        out.append(s)
    return out

def add_show(con: sqlite3.Connection, s: Show) -> Show:
    if s.max_seats == -1:
        s.max_seats = s.theater.seats
    q = "insert into show(date, mid, tid, max_seats, seats) values (?, ?, ?, ?, 0) returning sid;"
    res = con.execute(q, (s.startTime.isoformat(), s.movie.mid, s.theater.tid, s.max_seats))
    s.sid = res.fetchone()[0]
    return s

def book_show(con: sqlite3.Connection, sid: int, count: int = 1):
    q = "update show set seats = seats + ? where sid = ?;"
    res = con.execute(q, (count, sid))

