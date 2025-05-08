# Simple File Transfer
https://github.com/alperyzx/simpleFileTransfer

A lightweight, browser-based file transfer solution that allows for easy sharing of files between devices on the same network. Built using Python's HTTP server capabilities with a modern web interface.

## Features

- **Easy File Sharing**: Upload and download files through a clean web interface
- **Drag & Drop Support**: Simply drag files to upload them
- **Mobile Compatible**: Scan a QR code to connect from mobile devices
- **Password Protection**: Secure access with password authentication
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **No Installation Required**: Uses Python's built-in modules
- **File Management**: View recently uploaded files
- **Progress Tracking**: See upload progress in real-time
- **Large File Support**: Upload files up to 700MB each (1GB total)
- **Admin Controls**: Change password and upload directory (from host device)

## Quick Start

### Installation

1. Clone or download this repository
2. Run the appropriate script for your platform:
   - **Windows**: Double-click `run.bat`
   - **macOS/Linux**: Open terminal and run `./run.sh`
3. Set a password when prompted
4. Access the server from your browser

### Requirements

- Python 3.6 or higher (automatically installed if missing)
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Network connectivity between devices

## Usage

### Hosting the Server

1. Run the startup script for your platform
2. Set a password when prompted (first run only)
3. Note the server URL displayed in the terminal
4. Keep the terminal window open while sharing files

### Accessing the Server

1. On the host device: Visit `http://localhost:8000`
2. From other devices on the same network: Visit `http://[HOST_IP]:8000`
   - Where `[HOST_IP]` is the IP address shown in the terminal
   - Alternatively, scan the QR code displayed on the host

### Sharing Files

1. Log in with the password you set
2. Drag files onto the upload area or click to select files
3. Wait for uploads to complete
4. Files will appear in the list below for download

## Security Considerations

- Access is password-protected
- Session timeout after 30 minutes of inactivity
- Brute force attack protection
- Host-only administrative functions
- Files are stored on the host device in the `uploaded` directory (configurable)

## Advanced Configuration

### Changing Upload Directory

1. Click the folder icon (📁) in the top right
2. Enter the full path to your desired directory
3. The server will create the directory if it doesn't exist

### Changing Password

1. Click the key icon (🔑) in the top right
2. Enter your new password
3. All existing sessions will be invalidated

## Troubleshooting

- **Cannot access server from another device**: Check firewall settings and ensure devices are on the same network
- **Upload fails**: Check file size (max 700MB per file) and total upload size (max 1GB)
- **Permission errors**: Ensure the upload directory has write permissions
- **Server won't start**: Verify Python is installed correctly

## License

This project is open-source and available under the MIT License.

## Acknowledgments

- Built with Python's `http.server` module
- Uses [QRCode.js](https://github.com/davidshimjs/qrcodejs) for QR code generation
