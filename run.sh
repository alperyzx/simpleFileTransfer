#!/bin/bash

echo "Simple File Transfer Server - Starting..."

# Function to detect package manager and install Python
install_python() {
    # Detect OS and package manager
    if command -v apt-get &>/dev/null; then
        echo "Detected Debian/Ubuntu system"
        sudo apt-get update && sudo apt-get install -y python3 python3-pip
    elif command -v dnf &>/dev/null; then
        echo "Detected Fedora system"
        sudo dnf install -y python3 python3-pip
    elif command -v yum &>/dev/null; then
        echo "Detected CentOS/RHEL system"
        sudo yum install -y python3 python3-pip
    elif command -v pacman &>/dev/null; then
        echo "Detected Arch Linux system"
        sudo pacman -Sy python python-pip
    elif command -v brew &>/dev/null; then
        echo "Detected macOS with Homebrew"
        brew install python
    else
        echo "Could not detect package manager. Please install Python manually from https://www.python.org/downloads/"
        return 1
    fi

    if [ $? -eq 0 ]; then
        echo "Python installed successfully!"
        return 0
    else
        echo "Failed to install Python. Please install it manually from https://www.python.org/downloads/"
        return 1
    fi
}

# Check if .venv exists and use it
if [ -f ".venv/bin/python" ]; then
    echo "Using virtual environment"
    PYTHON=".venv/bin/python"
else
    # Find highest Python version
    VERSIONS=()

    # Check for python3 command
    if command -v python3 &>/dev/null; then
        VERSIONS+=("python3")
    fi

    # Look for specific Python versions
    for v in 3.12 3.11 3.10 3.9 3.8 3.7 3.6; do
        if command -v python$v &>/dev/null; then
            VERSIONS+=("python$v")
        fi
    done

    # Fall back to any python in path
    if command -v python &>/dev/null; then
        VERSIONS+=("python")
    fi

    if [ ${#VERSIONS[@]} -eq 0 ]; then
        echo "Python not found. Would you like to install Python? (y/n)"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            install_python
            if [ $? -eq 0 ]; then
                # Try to find Python again after installation
                if command -v python3 &>/dev/null; then
                    PYTHON="python3"
                elif command -v python &>/dev/null; then
                    PYTHON="python"
                else
                    echo "Python installation seemed successful but Python command not found. Please restart the terminal and try again."
                    exit 1
                fi
            else
                exit 1
            fi
        else
            echo "Python installation cancelled. Python 3.6 or higher is required to run this application."
            exit 1
        fi
    else
        # Use the first (highest) version found
        PYTHON="${VERSIONS[0]}"
    fi

    # Verify it's Python 3
    $PYTHON -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Requires Python 3.6 or higher."
        exit 1
    fi
fi

echo "Using Python: $PYTHON"
$PYTHON httpServer.py
