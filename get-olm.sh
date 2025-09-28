#!/bin/bash

# Get Olm - Cross-platform installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/fosrl/olm/refs/heads/main/get-olm.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# GitHub repository info
REPO="fosrl/olm"
GITHUB_API_URL="https://api.github.com/repos/${REPO}/releases/latest"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get latest version from GitHub API
get_latest_version() {
    local latest_info
    
    if command -v curl >/dev/null 2>&1; then
        latest_info=$(curl -fsSL "$GITHUB_API_URL" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        latest_info=$(wget -qO- "$GITHUB_API_URL" 2>/dev/null)
    else
        print_error "Neither curl nor wget is available. Please install one of them." >&2
        exit 1
    fi
    
    if [ -z "$latest_info" ]; then
        print_error "Failed to fetch latest version information" >&2
        exit 1
    fi
    
    # Extract version from JSON response (works without jq)
    local version=$(echo "$latest_info" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    
    if [ -z "$version" ]; then
        print_error "Could not parse version from GitHub API response" >&2
        exit 1
    fi
    
    # Remove 'v' prefix if present
    version=$(echo "$version" | sed 's/^v//')
    
    echo "$version"
}

# Detect OS and architecture
detect_platform() {
    local os arch
    
    # Detect OS
    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        FreeBSD*)   os="freebsd" ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
    
    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        arm64|aarch64)  arch="arm64" ;;
        armv7l|armv6l)  
            if [ "$os" = "linux" ]; then
                if [ "$(uname -m)" = "armv6l" ]; then
                    arch="arm32v6"
                else
                    arch="arm32"
                fi
            else
                arch="arm64"  # Default for non-Linux ARM
            fi
            ;;
        riscv64)        
            if [ "$os" = "linux" ]; then
                arch="riscv64"
            else
                print_error "RISC-V architecture only supported on Linux"
                exit 1
            fi
            ;;
        *)
            print_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    
    echo "${os}_${arch}"
}

# Get installation directory
get_install_dir() {
    local platform="$1"
    
    if [[ "$platform" == *"windows"* ]]; then
        echo "$HOME/bin"
    else
        # For Unix-like systems, prioritize system-wide directories for sudo access
        # Check in order of preference: /usr/local/bin, /usr/bin, ~/.local/bin
        if [ -d "/usr/local/bin" ]; then
            echo "/usr/local/bin"
        elif [ -d "/usr/bin" ]; then
            echo "/usr/bin"
        else
            # Fallback to user directory if system directories don't exist
            echo "$HOME/.local/bin"
        fi
    fi
}

# Check if we need sudo for installation
need_sudo() {
    local install_dir="$1"
    
    # If installing to system directory and we don't have write permission, need sudo
    if [[ "$install_dir" == "/usr/local/bin" || "$install_dir" == "/usr/bin" ]]; then
        if [ ! -w "$install_dir" ] 2>/dev/null; then
            return 0  # Need sudo
        fi
    fi
    return 1  # Don't need sudo
}

# Download and install olm
install_olm() {
    local platform="$1"
    local install_dir="$2"
    local binary_name="olm_${platform}"
    local exe_suffix=""
    
    # Add .exe suffix for Windows
    if [[ "$platform" == *"windows"* ]]; then
        binary_name="${binary_name}.exe"
        exe_suffix=".exe"
    fi
    
    local download_url="${BASE_URL}/${binary_name}"
    local temp_file="/tmp/olm${exe_suffix}"
    local final_path="${install_dir}/olm${exe_suffix}"
    
    print_status "Downloading olm from ${download_url}"
    
    # Download the binary
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$download_url" -O "$temp_file"
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
    
    # Check if we need sudo for installation
    local use_sudo=""
    if need_sudo "$install_dir"; then
        print_status "Administrator privileges required for system-wide installation"
        if command -v sudo >/dev/null 2>&1; then
            use_sudo="sudo"
        else
            print_error "sudo is required for system-wide installation but not available"
            exit 1
        fi
    fi
    
    # Create install directory if it doesn't exist
    if [ -n "$use_sudo" ]; then
        $use_sudo mkdir -p "$install_dir"
    else
        mkdir -p "$install_dir"
    fi
    
    # Move binary to install directory
    if [ -n "$use_sudo" ]; then
        $use_sudo mv "$temp_file" "$final_path"
        $use_sudo chmod +x "$final_path"
    else
        mv "$temp_file" "$final_path"
        chmod +x "$final_path"
    fi
    
    print_status "olm installed to ${final_path}"
    
    # Check if install directory is in PATH (only warn for non-system directories)
    if [[ "$install_dir" != "/usr/local/bin" && "$install_dir" != "/usr/bin" ]]; then
        if ! echo "$PATH" | grep -q "$install_dir"; then
            print_warning "Install directory ${install_dir} is not in your PATH."
            print_warning "Add it to your PATH by adding this line to your shell profile:"
            print_warning "  export PATH=\"${install_dir}:\$PATH\""
        fi
    fi
}

# Verify installation
verify_installation() {
    local install_dir="$1"
    local exe_suffix=""
    
    if [[ "$PLATFORM" == *"windows"* ]]; then
        exe_suffix=".exe"
    fi
    
    local olm_path="${install_dir}/olm${exe_suffix}"
    
    if [ -f "$olm_path" ] && [ -x "$olm_path" ]; then
        print_status "Installation successful!"
        print_status "olm version: $("$olm_path" --version 2>/dev/null || echo "unknown")"
        return 0
    else
        print_error "Installation failed. Binary not found or not executable."
        return 1
    fi
}

# Main installation process
main() {
    print_status "Installing latest version of olm..."
    
    # Get latest version
    print_status "Fetching latest version from GitHub..."
    VERSION=$(get_latest_version)
    print_status "Latest version: v${VERSION}"
    
    # Set base URL with the fetched version
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    
    # Detect platform
    PLATFORM=$(detect_platform)
    print_status "Detected platform: ${PLATFORM}"
    
    # Get install directory
    INSTALL_DIR=$(get_install_dir "$PLATFORM")
    print_status "Install directory: ${INSTALL_DIR}"
    
    # Inform user about system-wide installation
    if [[ "$INSTALL_DIR" == "/usr/local/bin" || "$INSTALL_DIR" == "/usr/bin" ]]; then
        print_status "Installing system-wide for sudo access"
    fi
    
    # Install olm
    install_olm "$PLATFORM" "$INSTALL_DIR"
    
    # Verify installation
    if verify_installation "$INSTALL_DIR"; then
        print_status "olm is ready to use!"
        if [[ "$INSTALL_DIR" == "/usr/local/bin" || "$INSTALL_DIR" == "/usr/bin" ]]; then
            print_status "olm is installed system-wide and accessible via sudo"
        fi
        if [[ "$PLATFORM" == *"windows"* ]]; then
            print_status "Run 'olm --help' to get started"
        else
            print_status "Run 'olm --help' or 'sudo olm --help' to get started"
        fi
    else
        exit 1
    fi
}

# Run main function
main "$@"