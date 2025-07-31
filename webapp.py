#!/usr/bin/env python

"""
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/vulnerable-web-app
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/vulnerable-web-app/graphs/contributors
//  -------------------------------------------------------------
"""

from http.server import BaseHTTPRequestHandler, HTTPServer,ThreadingHTTPServer
from os import remove, path, environ
from contextlib import suppress, redirect_stdout
from urllib import parse as urllib_parse, request
from json import dumps
from sqlite3 import connect, register_adapter, register_converter
from hashlib import sha512
from random import randint
from http.cookies import SimpleCookie
from platform import uname
from subprocess import PIPE, STDOUT, Popen, check_output
from datetime import datetime, UTC, timedelta
from collections import deque
from logging import getLogger, Formatter, INFO, StreamHandler
from logging.handlers import RotatingFileHandler
from ast import parse as ast_parse
from sys import executable
from functools import wraps
from io import StringIO

SESSIONS = {}
BASE_TEMPLATE = b""
LOGIN_TEMPLATE = b""
URL = "/"
PATH = path.dirname(path.realpath(__file__))

DATABASE = path.join(PATH,"database.db")
EXTERNAL_FOLDER = path.join(PATH,"external")
TEMPLATE_FOLDER = path.join(PATH,"template")
LOGS_FOLDER = path.join(PATH,"logs")
LOGS_FILE = path.join(LOGS_FOLDER,"httpd.log")

LOGGER = getLogger("httpd")
rfh = RotatingFileHandler(LOGS_FILE, mode='wa', maxBytes=10*1024*1024, backupCount=5)
rfh.setFormatter(Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
LOGGER.addHandler(rfh)
LOGGER.addHandler(StreamHandler())
LOGGER.setLevel(INFO)
LOGGER.info("Logging Started")

with suppress(Exception):
    LOGGER.info("Deleting old database.db")
    remove(DATABASE)

def adapt_datetime_iso(time):
    return time.isoformat()

def convert_datetime(time):
    return datetime.fromisoformat(val.decode())

register_adapter(datetime, adapt_datetime_iso)
register_converter("datetime", convert_datetime)

SALT = environ["salt"].encode("utf-8") if "salt" in environ else b""
USERS = [("admin", sha512(b"admin"+SALT).hexdigest(),"IT","sysinfo,tickets,ping,logs,external,sql",1),
         ("john", sha512(b"john"+SALT).hexdigest(),"HR","tickets",0),
         ("jane", sha512(b"jane"+SALT).hexdigest(),"Sales","tickets",0),
         ("joe", sha512(b"joe"+SALT).hexdigest(),"R&D","sysinfo,tickets,ping,external",0)]
TICKETS = [("john","IT, could you please help Joe Doe log into VPN"),
          ("jane","IT, we are unable to access the \\\\SALES")]

with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
    LOGGER.info("Creating new database.db")
    cursor = connection.cursor()
    
    cursor.execute("CREATE TABLE users (id integer PRIMARY KEY, username text, hash text, department text, access text, is_admin BOOLEAN DEFAULT 0 NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);")
    cursor.execute("CREATE TABLE tickets (id integer PRIMARY KEY, username text, ticket text, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);")
    cursor.execute("CREATE TABLE ping (id integer PRIMARY KEY, username text, ping text, output text, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);")
    cursor.executemany("INSERT into users(username, hash, department, access, is_admin) values(?,?,?,?,?)", USERS)
    cursor.executemany("INSERT into tickets(username, ticket) values(?,?)", TICKETS)

with open(path.join(TEMPLATE_FOLDER,"home.html"),"rb") as f:
    BASE_TEMPLATE = f.read()
with open(path.join(TEMPLATE_FOLDER,"login.html"),"rb") as f:
    LOGIN_TEMPLATE = f.read()

class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
         self.session = None
         super().__init__(*args, **kwargs)

    def needs_login(f):
        @wraps(f)
        def wrapper(self, *args, **kws):
            session = None
            cookies = SimpleCookie(self.headers.get('Cookie'))
            if 'session_id' in cookies:
                    if cookies['session_id'].value in SESSIONS:
                        session = SESSIONS[cookies['session_id'].value]
            if session:
                return f(self, *args, **kws)
            else:
                return self.redirect(URL)
        return wrapper

    def logged_in(f):
        @wraps(f)
        def wrapper(self, *args, **kws):
            if self.session:
                return f(self, *args, **kws)
            else:
                self.redirect(URL)
                return
        return wrapper

    def admin_only(f):
        @wraps(f)
        def wrapper(self, *args, **kws):
            cookies = SimpleCookie(self.headers.get('Cookie'))
            if "is_admin" in cookies:
                if cookies['is_admin'].value == "1":
                    return f(self, *args, **kws)
            return b"Admin Privileges Needed"
        return wrapper

    def check_access(func_=None, access=None):
        def _check_access(f):
            @wraps(f)
            def wrapper(self, *args, **kws):
                cookies = SimpleCookie(self.headers.get('Cookie'))
                if "access" in cookies:
                    if access in cookies['access'].value:
                        return f(self, *args, **kws)
                return b"Access Needed"
            return wrapper

        if callable(func_):
            return _check_access(func_)
        else:
            return _check_access

    def render_page(func_=None, file=None):
        def _render_page(f):
            @wraps(f)
            def wrapper(self, *args, **kws):
                with open(path.join(TEMPLATE_FOLDER,file),"rb") as fi:
                    content = fi.read()
                    items = f(self, *args, **kws)
                    for item in items:
                        content = content.replace(item[0], item[1])
                    return content
                return b"Access Needed"
            return wrapper

        if callable(func_):
            return _render_page(func_)
        else:
            return _render_page

    def gen_cookie(self, row, max_age):
        session_id = "".join(str(randint(1, 9)) for _ in range(5))
        #end_time = datetime.now() + timedelta(days=1)
        SESSIONS[session_id] = {"username":row[1], "department": row[3],"access":row[4], "is_admin":row[5]}
        cookie1 = SimpleCookie()
        cookie1['session_id'] = session_id
        cookie1['session_id']['path'] = '/'
        cookie1['session_id']['max-age'] = max_age
        cookie2 = SimpleCookie()
        cookie2['is_admin'] = row[5]
        cookie2['is_admin']['path'] = '/'
        cookie2['is_admin']['max-age'] = max_age
        cookie3 = SimpleCookie()
        cookie3['access'] = row[4]
        cookie3['access']['path'] = '/'
        cookie3['access']['max-age'] = max_age
        cookie4 = SimpleCookie()
        cookie4['department'] = row[3]
        cookie4['department']['path'] = '/'
        cookie4['department']['max-age'] = max_age
        cookies = [('Set-Cookie', cookie1.output(header='', sep='')),('Set-Cookie', cookie2.output(header='', sep='')),('Set-Cookie', cookie3.output(header='', sep='')),('Set-Cookie', cookie4.output(header='', sep=''))]
        return cookies

    def redirect(self, url):
        self.send_response(301)
        self.send_header('Location', url)
        self.end_headers()

    def add_user(self, username, password):
        with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
            cursor = connection.cursor()
            results = cursor.execute("SELECT * FROM users WHERE username='%s'" % (username)).fetchall()
            if not results:
                cursor.execute("INSERT into users(username, hash, department, access, is_admin) values(?,?,?,?,?)", (username, sha512(password.encode("utf-8")+SALT).hexdigest(),"none","sysinfo,tickets",0))
                return True
        return False

    def check_creds(self, username, password):
        try:
            with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
                cursor = connection.cursor()
                valid_username = cursor.execute("SELECT * FROM users WHERE username='%s'" % (username)).fetchone()
                if valid_username:
                    valid_password = cursor.execute("SELECT * FROM users WHERE username='%s' AND hash='%s'" % (username,sha512(password.encode("utf-8")+SALT).hexdigest())).fetchone()
                    if valid_password:
                        return ["valid",valid_password]
                    else:
                        return ["password",valid_username]
                else:
                    return ["username", username]
        except Exception as e:
            return ["error",str(e).encode("utf-8")] 

    def check_logged_in(self):
        cookies = SimpleCookie(self.headers.get('Cookie'))
        if 'session_id' in cookies:
                if cookies['session_id'].value in SESSIONS:
                    return SESSIONS[cookies['session_id'].value]
        return False

    def clear_session(self):
        cookies = SimpleCookie(self.headers.get('Cookie'))
        if 'session_id' in cookies:
                if cookies['session_id'].value in SESSIONS:
                    self.log_message("%s logged out" % SESSIONS[cookies['session_id'].value]["username"])
                    del SESSIONS[cookies['session_id'].value]
        return False

    @logged_in
    @render_page(file="sysinfo.html")
    def sysinfo_section(self):
        temp = b""
        for row in [(attr,value) for attr,value in zip(['system', 'nodename', 'release', 'version', 'root'], uname())]:
            temp += f"<div>{row[0]}: {row[1]}</div>".encode("utf-8")
        return [((b"{{sysinfo-results}}"),temp)]

    @logged_in
    @check_access(access="logs")
    @render_page(file="logs.html")
    def logs_section(self):
        temp = b""
        with open(LOGS_FILE,"r") as f:
            last_lines =  deque(f,maxlen=10)
            if last_lines:
                for row in last_lines:
                    temp += f"<div>{row.strip()}</div>".encode("utf-8")
        return [((b"{{logs-results}}"),temp)]

    @logged_in
    @check_access(access="tickets")
    @render_page(file="tickets.html")
    def tickets_section(self):
        temp = b""
        with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
            results = None
            cursor = connection.cursor()
            cookies = SimpleCookie(self.headers.get('Cookie'))
            if "is_admin" in cookies:
                if cookies['is_admin'].value == "1":
                    results = cursor.execute("SELECT * FROM tickets ORDER BY id DESC LIMIT 10").fetchall()
                else:
                    results = cursor.execute("SELECT * FROM tickets WHERE username='%s' ORDER BY id DESC LIMIT 10" % self.session["username"]).fetchall()
            else:
                results = cursor.execute("SELECT * FROM tickets WHERE username='%s' ORDER BY id DESC LIMIT 10" % self.session["username"]).fetchall()
            if results:
                for row in reversed(results):
                    temp += f"<div>[{row[3]}] {row[1]}: {row[2]}</div>".encode("utf-8")
        return [((b"{{tickets-results}}"),temp)]

    @logged_in
    @check_access(access="ping")
    @render_page(file="ping.html")
    def ping_section(self):
        temp = b""
        with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
            cursor = connection.cursor()
            results = cursor.execute("SELECT * FROM ping WHERE username='%s' ORDER BY id DESC LIMIT 10" % self.session["username"]).fetchall()
            if results:
                for row in reversed(results):
                    temp += f"<div>[{row[4]}] {row[2]} -> {row[3]}</div>".encode("utf-8")
        return [((b"{{ping-results}}"),temp)]

    @logged_in
    @check_access(access="external")
    @render_page(file="external.html")
    def external_section(self):
        return [((b"{{external-results}}"),b"")]

    @logged_in
    @check_access(access="sql")
    @render_page(file="sql.html")
    def sql_section(self):
        return [((b"{{sql-results}}"),b"")]

    def run_external_module(self,link=None):
        ret = b""
        if link != None:
            with suppress():
                Valid = False
                parsed = urllib_parse.urlparse(link)
                filename = path.basename(parsed.path)
                file_content = b""
                with request.urlopen(link) as response, open(f"{path.join(EXTERNAL_FOLDER,filename)}","wb") as f:
                    file_content = response.read()
                    try:
                        ast_parse(file_content)
                        f.write(file_content)
                        Valid = True
                    except:
                        Valid = False
                if Valid:
                    with Popen([executable,f"{path.join(EXTERNAL_FOLDER,filename)}"], stdout=PIPE, stderr=STDOUT, close_fds=True) as process:
                         ret = process.communicate()[0]
                    #captured_output = StringIO()
                    #with redirect_stdout(captured_output):
                    #    exec(file_content)
                    #ret = captured_output.getvalue().encode("utf-8")
        return ret

    def run_sql_query(self,query=None):
        ret = b""
        try:
            if query != None:
                with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
                    cursor = connection.cursor()
                    results = cursor.execute(query)
                    if results:
                        if results.rowcount != -1:
                            ret += f"Row Count ({results.rowcount}) ".encode("utf-8")
                        for row in results:
                            ret += str(row).encode("utf-8")
        except Exception as e:
            ret = str(e).encode("utf-8")
        return ret

    def get_user(self,id_=None):
        ret = b""
        try:
            if id_ != None:
                with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
                    cursor = connection.cursor()
                    results = cursor.execute("SELECT * FROM users WHERE id='%s'" % (id_)).fetchone()
                    return dumps(results).encode('utf-8')
        except Exception as e:
            ret = str(e).encode("utf-8")
        return ret

    @logged_in
    @check_access(access="logs")
    def read_logs(self, file, search=None, recent_rows=10):
        temp_logs = b""
        if search:
            with open(file,"r") as f:
                lines = f.readlines()
                found = [line for line in lines if search in line]
                if found:
                    temp_logs += f"<div>Number of lines: {len(found)}</div>".encode("utf-8")
                    for line in found[-recent_rows:]:
                        temp_logs += f"<div>{line.strip()}</div>".encode("utf-8")
                if temp_logs == b"":
                    temp_logs = f"<div>No match found: {search}</div>".encode("utf-8")
        else:
            with open(file,"rb") as f:
                temp_logs += f.read()
        return temp_logs

    @logged_in
    @check_access(access="tickets")
    def add_ticket(self, ticket):
        with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT into tickets(username, ticket) values(?,?)", (self.session["username"], ticket))
            return True
        return False

    @logged_in
    @check_access(access="ping")
    def add_ping(self, ping):
        with Popen("ping -c 1 " + ping, stdout=PIPE, stderr=STDOUT, shell=True) as process, connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT into ping(username, ping, output) values(?,?,?)", (self.session["username"], ping, process.communicate()[0].decode("utf-8")))
            return True
        return False

    @logged_in
    def render_home_page(self):
        content = b""
        cookies = SimpleCookie(self.headers.get('Cookie'))
        if "access" in cookies:
            for access in cookies["access"].value.split(","):
                content += getattr(self, f"{access}_section" , None)()
        return BASE_TEMPLATE.replace(b"{{body}}",content)


    def render_login_page(self):
        return BASE_TEMPLATE.replace(b"{{body}}",LOGIN_TEMPLATE)

    def msg_page(self, msg, prev=None):
        with open(path.join(TEMPLATE_FOLDER,"msg.html"),"rb") as fi:
            if prev:
                return fi.read().replace(b"{{msg-result}}",msg).replace(b"{{msg-prev}}",prev).replace(b"{{msg-page}}",b"Return")
            else:
                return fi.read().replace(b"{{msg-result}}",msg).replace(b"{{msg-prev}}",b"/").replace(b"{{msg-page}}",b"Home")

    def send_content(self, status, headers, content=None):
        if status:
            self.send_response(status)
        if headers:
            for header in headers:
                self.send_header(header[0], header[1])
        self.end_headers()
        if content != None:
            if self.check_logged_in():
                status = b'''<li class="nav-item"><a href="/logout"> <i class="fa fa-sign-out"></i></a></li>'''
                content = content.replace(b"{{status}}", status)
            else:
                content = content.replace(b"{{status}}", b"") 
            self.wfile.write(content)

    def send_content_raw(self, status, headers, content=None):
        if status:
            self.send_response(status)
        if headers:
            for header in headers:
                self.send_header(header[0], header[1])
        self.end_headers()
        if content != None:
            self.wfile.write(content)

    def do_GET(self):
        parsed_url = urllib_parse.urlparse(self.path)
        get_request_data = urllib_parse.parse_qs(parsed_url.query)
        self.session = self.check_logged_in()
        if parsed_url.path == "/" or parsed_url.path == "/home" or parsed_url.path == "/login":
            if self.session:
                self.send_content(200, [('Content-type', 'text/html')], self.render_home_page()) 
                return
            else:
                self.send_content(200, [('Content-type', 'text/html')], self.render_login_page())
                return
        elif parsed_url.path == "/logs":
            if parsed_url.query.startswith("file=") and "file" in get_request_data:
                self.send_content(200, [('Content-type', 'text/html')], self.read_logs(get_request_data["file"][0]))
                return
            elif parsed_url.query.startswith("search=") and "search" in get_request_data:
                self.send_content(200, [('Content-type', 'text/html')], self.read_logs(LOGS_FILE,get_request_data["search"][0]))
                return
        elif parsed_url.path == "/logout":
            self.clear_session()
            self.redirect(URL)
            return
        elif parsed_url.path == "/redirect" and "url" in get_request_data:
            self.redirect(get_request_data["url"][0])
            return
        elif parsed_url.path == '/favicon.ico':
            self.send_content(204, None, None)
            return
        elif parsed_url.path == '/user' and "id" in get_request_data:
            self.send_content_raw(200, [('Content-type', 'application/json')], self.get_user(get_request_data["id"][0]))
            return
        else:
            self.send_content(404, [('Content-type', 'text/html')], self.msg_page(f"Error: The requested URL {urllib_parse.unquote(parsed_url.path)} was not found".encode("utf-8")))
            #self.send_content(204, None, None)
            return

    def do_POST(self):
        parsed_url = urllib_parse.urlparse(self.path)
        post_request_data_length = int(self.headers.get('content-length'))
        post_request_data = urllib_parse.parse_qs(str(self.rfile.read(post_request_data_length),"UTF-8"))
        self.session = self.check_logged_in()
        if parsed_url.path == "/login" and "username" in post_request_data and "password" in post_request_data:
            ret = self.check_creds(post_request_data['username'][0],post_request_data['password'][0])
            if isinstance(ret, list) and ret[0] == "valid":
                self.send_content(302, self.gen_cookie(ret[1],60*15)+[('Location', URL)], None)
                self.log_message("%s logged in" % post_request_data['username'][0])
                return
            elif isinstance(ret, list) and ret[0] == "password":
                if "debug" in post_request_data:
                    if post_request_data["debug"][0] == "1":
                        self.send_content(302, self.gen_cookie(ret[1],60*15)+[('Location', URL)], None)
                        self.log_message("%s logged in" % post_request_data['username'][0])
                        return
                self.send_content(401, [('Content-type', 'text/html')], self.msg_page(f"Password is wrong".encode("utf-8"), b"login"))
                return
            elif isinstance(ret, list) and ret[0] == "username" or isinstance(ret, list) and ret[0] == "error":
                self.send_content(401, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data['username'][0]} doesn't exist".encode("utf-8"), b"login"))
                return
        elif parsed_url.path == "/register" and "username" in post_request_data and "password" in post_request_data:
            ret = self.add_user(post_request_data["username"][0],post_request_data["password"][0])
            if ret:
                self.send_content(200, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data["username"][0]} created".encode("utf-8"), b"login"))
            else:
                self.send_content(200, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data["username"][0]} was not created".encode("utf-8"), b"login"))
            return
        elif parsed_url.path == "/add" and "ticket" in post_request_data:
            self.add_ticket(post_request_data["ticket"][0])
            self.redirect(URL)
            return
        elif parsed_url.path == "/ping" and "ping" in post_request_data:
            self.add_ping(post_request_data["ping"][0])
            self.redirect(URL)
            return
        elif parsed_url.path == "/external" and "link" in post_request_data:
            self.send_content(200, [('Content-type', 'text/html')], self.run_external_module(post_request_data["link"][0]))
            return
        elif parsed_url.path == "/sql" and "query" in post_request_data:
            self.send_content(200, [('Content-type', 'text/html')], self.run_sql_query(post_request_data["query"][0]))
            return

        self.send_content(404, [('Content-type', 'text/html')], self.msg_page(f"Error: The requested URL {parsed_url.path} was not found".encode("utf-8")))
        return

    #def send_error(self, code, message=None, explain=None):
    #    return

    def log_message(self, format, *args):
        LOGGER.info("[%s] [%s] %s" %(self.address_string(),self.log_date_time_string(),format%args))

    def info_msg(self, type, msg):
        return b'''<div id="info-message-box">{{1}}</div>'''.replace(b"{{1}}",msg)

    def wwwhandle(self):
        try:
            BaseHTTPRequestHandler.handle(self)
        except Exception as e:
            self.send_content(500, [('Content-type', 'text/html')], self.msg_page(f"Error: Internal Server Error {str(e)}".encode("utf-8")))

with ThreadingHTTPServer(('', 5142), handler) as server:
    LOGGER.info("HTTP server is running on port 5142... \nPress Ctrl+C to stop the server")
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    LOGGER.info("Server closed.")
