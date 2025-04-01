# Python
import http.server
import socketserver
from http import HTTPStatus
import os
import email
import json
from email import policy
import urllib.parse
import time
import uuid
import http.cookies
import socket
import logging
import shutil
import tempfile

login_attempts = {}  # Format: { client_ip: { "count": int, "lock_until": timestamp (optional) } }
PASSWORD = None  # Password will be set during first launch
SESSION_TIMEOUT = 1800  # Session timeout in seconds (30 minutes)
sessions = {}  # Format: {session_id: {'created_at': timestamp}}
UPLOAD_DIR = "uploaded"  # Default upload directory
MAX_FILE_SIZE = 1024 * 1024 * 700  # 700 MB file size limit
ALLOWED_EXTENSIONS = None  # Set to a list to restrict file types, None for no restriction
MAX_PASSWORD_LENGTH = 5  # Maximum password length

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class HTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Set a longer timeout (5 minutes)
    timeout = 300
    
    @staticmethod
    def get_server_ip():
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

    @staticmethod
    def create_session():
        session_id = str(uuid.uuid4())
        sessions[session_id] = {'created_at': time.time()}
        return session_id

    def get_current_session_id(self):
        """Get the current user's session ID from cookie"""
        if 'Cookie' in self.headers:
            cookie = http.cookies.SimpleCookie(self.headers['Cookie'])
            if 'session_id' in cookie:
                return cookie['session_id'].value
        return None

    def serve_password_setup_page(self, error_message=""):
        server_ip = self.get_server_ip()
        setup_page = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Set Password</title>
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
                .info {{
                    color: #666;
                    font-size: 0.85rem;
                    margin-bottom: 15px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Simple File Transfer</h2>
                <p class="info">Please set a password for the server<br>(max {MAX_PASSWORD_LENGTH} characters)</p>
                {f'<p class="error">{error_message}</p>' if error_message else ""}
                <form method="POST" action="/setup">
                    <input type="password" name="password" placeholder="Password" maxlength="{MAX_PASSWORD_LENGTH}" required>
                    <br>
                    <input type="password" name="confirm_password" placeholder="Confirm Password" maxlength="{MAX_PASSWORD_LENGTH}" required>
                    <br>
                    <input type="submit" value="Set Password">
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
        self.wfile.write(setup_page.encode("utf-8"))

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

    def is_host(self):
        # Check if the client is on the same machine as the server
        client_ip = self.client_address[0]
        return client_ip == "127.0.0.1" or client_ip == "::1" or client_ip == self.get_server_ip()

    def do_GET(self):
        global PASSWORD
        
        # Handle password setup if no password is set yet
        if PASSWORD is None:
            if not self.is_host():
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Server is being configured. Please wait for setup to complete.")
                return
            return self.serve_password_setup_page()
            
        if self.path.startswith("/download/"):
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
                
            # Extract the filename from the path
            filename = self.path[10:]  # Remove the '/download/' prefix
            filename = urllib.parse.unquote(filename)
            
            # Prevent directory traversal attacks
            if os.path.isabs(filename) or '..' in filename:
                self.send_error(HTTPStatus.FORBIDDEN, "Access denied")
                return
                
            # Create the full path using the current UPLOAD_DIR
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            # Check if the file exists
            if not os.path.isfile(file_path):
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return
                
            # Serve the file
            try:
                with open(file_path, 'rb') as file:
                    self.send_response(HTTPStatus.OK)
                    
                    # Determine content type (basic implementation)
                    content_type = "application/octet-stream"  # Default
                    if filename.endswith('.html'): content_type = 'text/html'
                    elif filename.endswith('.txt'): content_type = 'text/plain'
                    elif filename.endswith('.jpg') or filename.endswith('.jpeg'): content_type = 'image/jpeg'
                    elif filename.endswith('.png'): content_type = 'image/png'
                    elif filename.endswith('.gif'): content_type = 'image/gif'
                    elif filename.endswith('.pdf'): content_type = 'application/pdf'
                    
                    self.send_header("Content-type", content_type)
                    
                    # Properly encode filename for Content-Disposition header
                    # Use both filename and filename* parameters for compatibility
                    ascii_filename = filename.encode('ascii', 'replace').decode('ascii')
                    utf8_filename = filename.encode('utf-8')
                    
                    # Percent-encode the UTF-8 bytes for filename*
                    encoded_filename = ''
                    for byte in utf8_filename:
                        encoded_filename += f'%{byte:02X}'
                    
                    content_disp = f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}'
                    self.send_header("Content-Disposition", content_disp)
                    
                    # Get file size for Content-Length header
                    fs = os.fstat(file.fileno())
                    self.send_header("Content-Length", str(fs.st_size))
                    self.end_headers()
                    
                    # Copy the file to the response
                    shutil.copyfileobj(file, self.wfile)
                    
            except Exception as e:
                logging.error(f"Error serving file {filename}: {str(e)}")
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error serving file")
                
            return

        if self.path == "/isHost":
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            is_host = self.is_host()
            self.wfile.write(json.dumps({"isHost": is_host}).encode("utf-8"))
            return
            
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
        global PASSWORD, login_attempts, UPLOAD_DIR, sessions
        
        # Handle initial password setup
        if self.path == "/setup" and PASSWORD is None:
            if not self.is_host():
                self.send_response(403)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Only the host can set up the server.")
                return
                
            content_length = int(self.headers["Content-Length"])
            body = self.rfile.read(content_length)
            params = urllib.parse.parse_qs(body.decode("utf-8"))
            
            new_password = params.get("password", [""])[0]
            confirm_password = params.get("confirm_password", [""])[0]
            
            if not new_password:
                return self.serve_password_setup_page("Password cannot be empty.")
                
            if new_password != confirm_password:
                return self.serve_password_setup_page("Passwords do not match.")
                
            if len(new_password) > MAX_PASSWORD_LENGTH:
                return self.serve_password_setup_page(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")

            # Set the password
            PASSWORD = new_password
            
            # Redirect to main page after successful setup
            session_id = self.create_session()
            cookie = http.cookies.SimpleCookie()
            cookie["session_id"] = session_id
            cookie["session_id"]["path"] = "/"
            cookie["session_id"]["httponly"] = True
            
            self.send_response(302)
            self.send_header("Set-Cookie", cookie.output(header=""))
            self.send_header("Location", "/")
            self.end_headers()
            return
        
        if self.path == "/login":
            if PASSWORD is None:
                if self.is_host():
                    self.send_response(302)
                    self.send_header("Location", "/setup")
                    self.end_headers()
                    return
                else:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"Server is being configured. Please try again later.")
                    return
            
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
                    info["lock_until"] = int(curr_time) + 300
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

        if self.path == "/setUploadDir":
            try:
                if not self.is_host():
                    self.send_response(HTTPStatus.FORBIDDEN)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {"success": False, "error": "Only the host can change the upload directory"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return
                    
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                data = json.loads(body.decode())
                new_dir = data.get("uploadDir", "")
                
                if not new_dir:
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {"success": False, "error": "Upload directory not provided"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return
                
                # Create the directory if it doesn't exist
                if not os.path.exists(new_dir):
                    try:
                        os.makedirs(new_dir)
                    except Exception as e:
                        self.send_response(HTTPStatus.BAD_REQUEST)
                        self.send_header("Content-type", "application/json; charset=utf-8")
                        self.end_headers()
                        response = {"success": False, "error": f"Could not create directory: {str(e)}"}
                        self.wfile.write(json.dumps(response).encode("utf-8"))
                        return
                        
                # Check if the directory is writable
                if not os.access(new_dir, os.W_OK):
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {"success": False, "error": "Directory is not writable"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return
                    
                UPLOAD_DIR = new_dir
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.end_headers()
                response = {"success": True, "message": f"Upload directory changed to {new_dir}"}
                self.wfile.write(json.dumps(response).encode("utf-8"))
            except Exception as e:
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.end_headers()
                response = {"success": False, "error": str(e)}
                self.wfile.write(json.dumps(response).encode("utf-8"))

        elif self.path == "/upload":
            try:
                content_type = self.headers.get('Content-Type', '')
                if not content_type.startswith('multipart/form-data'):
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {"success": False, "error": "Invalid content type"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return

                # Get content length, use 0 if header is missing
                try:
                    content_length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    content_length = 0
                
                # Check if content is too large
                if content_length > MAX_FILE_SIZE:
                    self.send_response(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {
                        "success": False, 
                        "error": f"File too large. Maximum allowed size is {MAX_FILE_SIZE // (1024 * 1024)} MB"
                    }
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return
                
                # Create a temporary file to store the request data
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_path = temp_file.name
                    
                    # Read in manageable chunks
                    bytes_remaining = content_length
                    chunk_size = 8192  # 8KB chunks
                    
                    while bytes_remaining > 0:
                        chunk_size = min(chunk_size, bytes_remaining)
                        chunk = self.rfile.read(chunk_size)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        bytes_remaining -= len(chunk)
                
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "application/json; charset=utf-8")
                session_id = self.create_session()
                cookie = http.cookies.SimpleCookie()
                cookie["session_id"] = session_id
                cookie["session_id"]["path"] = "/"
                cookie["session_id"]["httponly"] = True
                self.send_header("Set-Cookie", cookie.output(header=""))
                self.end_headers()

                if not os.path.exists(UPLOAD_DIR):
                    os.makedirs(UPLOAD_DIR)
                
                # Now process the saved request data
                with open(temp_path, 'rb') as f:
                    body = f.read()
                
                # Clean up the temporary file
                os.unlink(temp_path)
                
                msg = email.message_from_bytes(
                    b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + body,
                    policy=policy.default
                )

                uploaded_files = []
                errors = []
                
                for part in msg.iter_parts():
                    if part.get_content_maintype() == "multipart":
                        continue
                    if part.get("Content-Disposition") is None:
                        continue
                    
                    filename = part.get_filename()
                    if not filename:
                        continue
                        
                    try:
                        decoded_header = email.header.decode_header(filename)
                        filename = "".join(
                            [text.decode(charset or "utf-8") if isinstance(text, bytes) else text
                             for text, charset in decoded_header]
                        )
                        
                        # Sanitize filename to prevent directory traversal
                        safe_filename = os.path.basename(filename)
                        
                        # Check for allowed extensions if configured
                        if ALLOWED_EXTENSIONS and not any(safe_filename.lower().endswith('.' + ext.lower()) for ext in ALLOWED_EXTENSIONS):
                            errors.append(f"File type not allowed: {safe_filename}")
                            continue
                        
                        # Handle filename conflicts by adding timestamp if file exists
                        target_path = os.path.join(UPLOAD_DIR, safe_filename)
                        if os.path.exists(target_path):
                            name, ext = os.path.splitext(safe_filename)
                            timestamp = int(time.time())
                            safe_filename = f"{name}_{timestamp}{ext}"
                            target_path = os.path.join(UPLOAD_DIR, safe_filename)
                        
                        # Get file content and check size
                        file_content = part.get_payload(decode=True)
                        if file_content and len(file_content) > MAX_FILE_SIZE:
                            errors.append(f"File too large: {safe_filename}")
                            continue
                            
                        # Write the file
                        with open(target_path, "wb") as output_file:
                            output_file.write(file_content)
                            
                        uploaded_files.append(safe_filename)
                        logging.info(f"Successfully uploaded: {safe_filename}")
                        
                    except Exception as e:
                        error_msg = f"Error processing {filename}: {str(e)}"
                        errors.append(error_msg)
                        logging.error(error_msg)

                # Check if any files were actually uploaded
                if not uploaded_files:
                    error_msg = "No files were uploaded"
                    if errors:
                        error_msg += f": {'; '.join(errors)}"
                    response = {"success": False, "error": error_msg}
                else:
                    response = {
                        "success": True, 
                        "files": uploaded_files
                    }
                    if errors:
                        response["warnings"] = errors
                
                self.wfile.write(json.dumps(response).encode("utf-8"))
                
            except Exception as e:
                logging.exception("Upload error")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.end_headers()
                response = {"success": False, "error": f"Upload failed: {str(e)}"}
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

                if len(new_password) > MAX_PASSWORD_LENGTH:
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-type", "application/json; charset=utf-8")
                    self.end_headers()
                    response = {"success": False, "error": f"Password must be at most {MAX_PASSWORD_LENGTH} characters"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                    return

                # Save the current session ID
                current_session_id = self.get_current_session_id()
                current_session = None
                if current_session_id and current_session_id in sessions:
                    current_session = sessions[current_session_id]

                # Invalidate all sessions by clearing the sessions dictionary
                sessions.clear()

                # Restore the current session if it existed
                if current_session and current_session_id:
                    sessions[current_session_id] = current_session

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
                response = {"success": True, "message": "Password changed successfully. All other sessions have been invalidated."}
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

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    if PASSWORD is None:
        print(f"No password set. Visit http://127.0.0.1:{PORT} to set up the server.")
    else:
        print(f"Password protection enabled. Use the configured password to log in.")
    print(f"Files will be uploaded to: {UPLOAD_DIR}")
    httpd.serve_forever()
