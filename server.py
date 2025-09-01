#!/bin/python3
import http.server
import http.client
from urllib.parse import urlparse
from typing import Tuple, Dict, Callable, Optional
import json

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Handler(http.server.BaseHTTPRequestHandler):
    """flask-inspired handler class.
    
    sets up headers, body and url parameters before calling respective route methods.

    functions:
    - @route("/login", method="POST")
    - send_error_json(msg)
        redirect with HTTPStatus.BAD_REQUEST, setting the msg.
    - redirect(locatoin, status=HTTPStatus.TEMPORARY_REDIRECTw)
        doesn't send json, relies on HTTP.
        It calls end_headers() at the end.
    - sendfile(path):
        sends ./path file to the write pipe
    - send_error_json(msg: str, status: int = http.HTTPStatus.BAD_REQUEST)
    - send_json_ok(self, msg: str, status: http.HTTPStatus = http.HTTPStatus.OK)
    - send_message(self, message: bytes, status: int = http.HTTPStatus.OK)
    - redirect(self, location: str, status: int = http.HTTPStatus.TEMPORARY_REDIRECT)

    It stores common variables like:
    - Headers: dict[str, str]
    - Url: urlparse.ParseResult
    - body: Any # Usually dict or list, converted from json

    as instance variables.
    """

    get_routes: Dict[str, Callable] = {}
    post_routes: Dict[str, Callable] = {}

    def _get_headers(self) -> dict:
        d = {}
        for name in self.headers:
            d[name] = self.headers[name];
        return d

    def send_error_json(self, msg: str, status: int = http.HTTPStatus.BAD_REQUEST):
        """sends {success: false, message: msg} with the status"""
        self.send_response(status)
        self.end_headers()
        self.wfile.write(
            json.dumps({"success": "false", "message": msg}).encode())
        
    def send_json_ok(self, msg: str, status: http.HTTPStatus = http.HTTPStatus.OK):
        """sends {success: true, message: "msg"} with the http status"""
        self.send_response(status)
        self.end_headers()
        self.wfile.write(json.dumps({"success": "true", "message": msg}).encode())

    def send_message(self, message: bytes, status: int = http.HTTPStatus.OK):
        """Used for sending OK messages, preconverted to bytes."""
        self.send_response(status)
        self.end_headers()
        self.wfile.write(message)

    def redirect(self,
                 location: str,
                 status: int = http.HTTPStatus.TEMPORARY_REDIRECT):
        self.send_response(status)
        self.send_header("Location", location)
        self.end_headers()

    def _preamble(self):
        """Common tasks for both GET and POST methods, like setting up headers"""
        self.Url = urlparse(self.path)
        self.Headers = self._get_headers()

    def do_GET(self):
        self._preamble()
        path=self.Url.path
        if not path in self.get_routes:
            self.send_error_json(f"no handler for {path}", status=http.HTTPStatus.NOT_FOUND)
            return
        try:
            self.get_routes[path](self)
        except Exception as e:
            logger.warn(e)
            self.send_error_json(f"do_GET: {path=} " + str(e))
            return
        if self._headers_buffer is None:
            self.send_error_json("handler didn't send anything", status=http.HTTPStatus.INTERNAL_SERVER_ERROR)
        self.end_headers()

    def do_POST(self):
        self._preamble()
        path=self.Url.path
        self.body = self._get_body_json()
        if not path in self.post_routes:
            self.send_error_json(f"no handler for {path}", status=http.HTTPStatus.NOT_FOUND)
            return
        try:
            self.post_routes[path](self)
        except Exception as e:
            logger.warn(path + str(e))
            self.send_error_json(f"do_POST: {path=} " + str(e))
            return
        if not hasattr(self, '_headers_buffer'):
            self.send_error_json("handler didn't send anything", status=http.HTTPStatus.INTERNAL_SERVER_ERROR)
        self.end_headers()

    def sendfile(self, path: str, content_type: str = "text/html"):
        """Opens ./path and sends it to client"""
        self.send_response(http.HTTPStatus.OK)
        self.send_header("Content-type", content_type)
        self.end_headers()
        with open("./" + path, "rb") as f:
            self.wfile.write(f.read())

    def _get_body_json(self):
        """reads body and json.loads it to dict/list"""
        body = self._get_body()
        return json.loads(body)

    def _get_body(self):
        length = self.headers.__getitem__('Content-Length')
        if length is None:
            self.send_error_json("no content length")
            return
        length = int(length)
        logger.debug(f"reading body, {length=}")
        body = self.rfile.read(length)
        logger.debug("done")
        return body

    @classmethod
    def route(cls, path: str, method: str = "GET") -> Callable:
        d = cls.get_routes
        if method == "POST":
            d = cls.post_routes
        def add_route(f: Callable) -> Callable:
            d[path] = f
            return f
        return add_route

