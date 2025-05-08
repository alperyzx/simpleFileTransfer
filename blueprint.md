# Simple File Transfer - Technical Blueprint

## 1. Project Overview

Simple File Transfer is a lightweight, secure file sharing solution designed for quick and easy file transfers between devices on the same network. The application runs a Python-based HTTP server that provides a browser-based interface for uploading and downloading files without complex configuration or additional software.

## 2. Architecture

### 2.1 System Architecture

```
+-------------------+      HTTP      +-------------------+
|                   | <------------> |                   |
|  Client Browser   |    Requests    |  Python HTTP      |
|  (Web Interface)  | -------------> |  Server           |
|                   |   Responses    |                   |
+-------------------+ <------------- +-------------------+
                                           |
                                           | File I/O
                                           v
                                    +-------------------+
                                    |                   |
                                    |  File System      |
                                    |  (Upload Dir)     |
                                    |                   |
                                    +-------------------+
```

### 2.2 Component Overview

- **HTTP Server (httpServer.py)**
  - Built on Python's `http.server` and `socketserver` modules
  - Handles authentication, session management, and file operations
  - Enforces security policies and access control

- **Web Interface (index.html)**
  - Responsive HTML/CSS/JS frontend
  - Supports drag-and-drop file uploads
  - Displays recently uploaded files
  - Generates QR code for easy mobile access

- **Launch Scripts (run.sh, run.bat)**
  - Cross-platform support for Linux/macOS and Windows
  - Automatic Python environment detection
  - Optional Python installation assistance

## 3. Core Features

### 3.1 File Management
- Upload files via browser interface (drag-and-drop or file picker)
- Maximum file size limit (700MB per file, 1GB total upload)
- Download files via direct links
- Recent files list showing the last 10 uploaded files
- Automatic handling of file name conflicts

### 3.2 Security
- Password protection for access control
- Session-based authentication with timeout (30 minutes)
- Brute force protection with account lockout
- Host-only administrative functions
- Path traversal attack prevention

### 3.3 User Interface
- Mobile-responsive design
- Upload progress indicator
- QR code for easy connection from mobile devices
- File type recognition with appropriate icons
- Clear error messaging and status updates

### 3.4 Administration
- Change password functionality
- Set custom upload directory
- Session management (auto-expiry and invalidation)

## 4. Technical Implementation

### 4.1 Server Implementation (httpServer.py)

#### Key Components:
- `HTTPRequestHandler`: Custom request handler extending SimpleHTTPRequestHandler
- Session management system using UUID-based tokens
- Password authentication with brute force protection
- File upload handler with size limits and security checks
- Download handler with proper content type and disposition headers

#### Configuration Parameters:
- `PASSWORD`: Server access password
- `SESSION_TIMEOUT`: Session expiry time (1800 seconds / 30 minutes)
- `UPLOAD_DIR`: Directory for storing uploaded files
- `MAX_FILE_SIZE`: Maximum allowed file size (700MB)
- `ALLOWED_EXTENSIONS`: Optional file type restriction

### 4.2 Frontend Implementation (index.html)

#### Key Components:
- Drag-and-drop upload area with progress indication
- XHR-based file upload with progress tracking
- Recent files list management
- QR code generator for server address
- Admin controls for host users

#### JavaScript Functions:
- `handleFiles()`: Validates file size and type
- `uploadFiles()`: Manages file upload process with progress tracking
- `updateFileList()`: Maintains list of recently uploaded files
- `getFileIcon()`: Determines appropriate icon based on file type

### 4.3 Security Considerations

- Authentication:
  - Password-based access control
  - Session management with secure cookies
  - Automatic timeout after inactivity

- Attack Prevention:
  - Brute force protection with IP-based lockout
  - Path traversal prevention
  - File size limits to prevent DoS attacks

- Administration:
  - Host-only admin functions
  - Password change invalidates all other sessions

## 5. Deployment Guidelines

### 5.1 System Requirements
- Python 3.6 or higher
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Network connectivity between devices

### 5.2 Installation
1. Clone or download the project files
2. Run the appropriate script for your platform:
   - Linux/macOS: `./run.sh`
   - Windows: `run.bat`
3. Set initial password when prompted
4. Access the server via browser at the displayed URL

### 5.3 Network Configuration
- Ensure the server is accessible on your network
- Configure firewall to allow connections on port 8000
- For external access, consider setting up port forwarding

## 6. Future Enhancements

### 6.1 Potential Improvements
- HTTPS support for encrypted transfers
- User management with multiple accounts
- File organization with folders
- Batch download functionality
- Direct sharing links with optional expiry
- Compression for large files
- Custom port configuration
- File preview for common formats

### 6.2 Scalability Considerations
- Implementation of a more robust web server (e.g., Flask, FastAPI)
- Database integration for file metadata
- Chunked file uploads for larger files
- Load balancing for high-volume scenarios

## 7. Troubleshooting

### 7.1 Common Issues
- Port conflicts with other services
- File permission problems in upload directory
- Network connectivity between devices
- Large file upload failures

### 7.2 Debugging
- Check server logs for error messages
- Verify network connectivity
- Ensure upload directory has proper permissions
- Test with smaller files to isolate size-related issues
