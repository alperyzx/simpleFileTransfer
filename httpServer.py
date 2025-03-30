# Python
# In your file `./venv/yz/httpServer.py`, update your authentication methods as follows:

import http.server
import socketserver
from http import HTTPStatus
import os
import email
import json
from email import policy
import base64
import urllib.parse
import time
import uuid
import http.cookies
import socket

login_attempts = {}  # Format: { client_ip: { "count": int, "lock_until": timestamp (optional) } }
PASSWORD = "1234"  # Change this to your preferred password
SESSION_TIMEOUT = 1800  # Session timeout in seconds (30 minutes)
sessions = {}  # Format: {session_id: {'created_at': timestamp}}

class HTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def get_server_ip(self):
        # New implementation to obtain the real outbound IP:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to an external server, doesn't actually send data.
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def is_authenticated(self):
        # Check for session cookie
        if 'Cookie' in self.headers:
            cookie = http.cookies.SimpleCookie(self.headers['Cookie'])
            if 'session_id' in cookie:
                session_id = cookie['session_id'].value
                if session_id in sessions:
                    if time.time() - sessions[session_id]['created_at'] < SESSION_TIMEOUT:
                        sessions[session_id]['created_at'] = time.time()
                        return True
                    else:
                        del sessions[session_id]
        return False

    def create_session(self):
        session_id = str(uuid.uuid4())
        sessions[session_id] = {'created_at': time.time()}
        return session_id

    def serve_login_page(self, error_message=""):
        server_ip = self.get_server_ip()
        login_page = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Required</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: \\\'Segoe UI\\\', Tahoma, Geneva, Verdana, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 60vh;
                    background-color: #f5f7fa;
                }}
                .container {{
                    background: white;
                    padding: 2rem;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                    width: 300px;
                    text-align: center;
                }}
                input[type=password] {{
                    width: 80%;
                    padding: 8px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }}
                input[type=submit] {{
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    background-color: #4a8cff;
                    color: white;
                    cursor: pointer;
                }}
                .error {{
                    color: red;
                    font-size: 0.9rem;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Please enter the password</h2>
                {f'<p class="error">{error_message}</p>' if error_message else ""}
                <form method="POST" action="/login">
                    <input type="password" name="password" placeholder="Password" required>
                    <br>
                    <input type="submit" value="Login">
                </form>
            </div>
            <script>
                const serverIp = "{server_ip}";
            </script>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(login_page.encode("utf-8"))

    def do_GET(self):
        if self.path == "/server-ip":
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            server_ip = self.get_server_ip()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"serverIp": server_ip}).encode("utf-8"))
            return
        if self.path == "/login":
            return self.serve_login_page()
        if not self.is_authenticated():
            # Redirect to custom login page instead of showing Basic auth dialog:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if self.path == "/":
            self.path = "index.html"
        # Serve file and add session cookie in response
        response = http.server.SimpleHTTPRequestHandler.do_GET(self)
        if self.is_authenticated():
            session_id = self.create_session()
            cookie = http.cookies.SimpleCookie()
            cookie["session_id"] = session_id
            cookie["session_id"]["path"] = "/"
            cookie["session_id"]["httponly"] = True
            self.send_header("Set-Cookie", cookie.output(header=""))
        return response

    def do_POST(self):
        global PASSWORD, login_attempts
        if self.path == "/login":
            client_ip = self.client_address[0]
            curr_time = time.time()
            # Check if this IP is locked out
            if client_ip in login_attempts:
                info = login_attempts[client_ip]
                if "lock_until" in info and curr_time < info["lock_until"]:
                    lock_remaining = int(info["lock_until"] - curr_time)
                    self.serve_login_page(f"Too many attempts. Please try again in {lock_remaining} seconds.")
                    return

            # Handle custom login form submission
            content_length = int(self.headers["Content-Length"])
            body = self.rfile.read(content_length)
            params = urllib.parse.parse_qs(body.decode("utf-8"))
            submitted_password = params.get("password", [""])[0]

            if submitted_password == PASSWORD:
                # On success, clear any recorded attempts for this IP.
                if client_ip in login_attempts:
                    del login_attempts[client_ip]
                session_id = self.create_session()
                cookie = http.cookies.SimpleCookie()
                cookie["session_id"] = session_id
                cookie["session_id"]["path"] = "/"
                cookie["session_id"]["httponly"] = True
                self.send_response(302)
                self.send_header("Set-Cookie", cookie.output(header=""))
                self.send_header("Location", "/")
                self.end_headers()
            else:
                # Increase failed login count.
                info = login_attempts.get(client_ip, {"count": 0})
                info["count"] += 1
                if info["count"] >= 3:
                    # Lock out for 5 minutes (300 seconds)
                    info["lock_until"] = curr_time + 300
                    login_attempts[client_ip] = info
                    self.serve_login_page("Too many attempts. Please try again in 5 minutes.")
                    return
                login_attempts[client_ip] = info
                self.serve_login_page("Incorrect password")
            return

        if not self.is_authenticated():
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if self.path == "/upload":
            try:
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "application/json; charset=utf-8")
                session_id = self.create_session()
                cookie = http.cookies.SimpleCookie()
                cookie["session_id"] = session_id
                cookie["session_id"]["path"] = "/"
                cookie["session_id"]["httponly"] = True
                self.send_header("Set-Cookie", cookie.output(header=""))
                self.end_headers()

                if not os.path.exists("uploaded"):
                    os.makedirs("uploaded")

                msg = email.message_from_bytes(
                    b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + body,
                    policy=policy.default
                )

                uploaded_files = []
                for part in msg.iter_parts():
                    if part.get_content_maintype() == "multipart":
                        continue
                    if part.get("Content-Disposition") is None:
                        continue
                    filename = part.get_filename()
                    if filename:
                        decoded_header = email.header.decode_header(filename)
                        filename = "".join(
                            [text.decode(charset or "utf-8") if isinstance(text, bytes) else text
                             for text, charset in decoded_header]
                        )
                        safe_filename = os.path.basename(filename)
                        with open(os.path.join("uploaded", safe_filename), "wb") as output_file:
                            output_file.write(part.get_payload(decode=True))
                        uploaded_files.append(safe_filename)

                response = {"success": True, "files": uploaded_files}
                self.wfile.write(json.dumps(response).encode("utf-8"))
            except Exception as e:
                response = {"success": False, "error": str(e)}
                self.wfile.write(json.dumps(response).encode("utf-8"))
        elif self.path == "/changePassword":
            try:
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                data = json.loads(body.decode())
                new_password = data.get("newPassword", "")
                if not new_password:
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {"success": False, "error": "newPassword not provided"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return
                PASSWORD = new_password
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "application/json; charset=utf-8")
                session_id = self.create_session()
                cookie = http.cookies.SimpleCookie()
                cookie["session_id"] = session_id
                cookie["session_id"]["path"] = "/"
                cookie["session_id"]["httponly"] = True
                self.send_header("Set-Cookie", cookie.output(header=""))
                self.end_headers()
                response = {"success": True, "message": "Password changed successfully."}
                self.wfile.write(json.dumps(response).encode("utf-8"))
            except Exception as e:
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.end_headers()
                response = {"success": False, "error": str(e)}
                self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

PORT = 8000
Handler = HTTPRequestHandler

if not os.path.exists("uploaded"):
    os.makedirs("uploaded")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    print(f"Password protection enabled. Use password: {PASSWORD}")
    httpd.serve_forever()
