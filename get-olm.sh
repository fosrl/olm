#!/bin/bash

# Get Olm - Cross-platform installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/fosrl/olm/refs/heads/main/get-olm.sh | bash
#
# Options (pass after `bash -s --`, e.g. `... | bash -s -- --version 1.10.1`):
#   --version <version>  Install a specific release instead of the latest.
#                        Can also be set with OLM_VERSION.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# GitHub repository info
REPO="fosrl/olm"
RELEASE_API_URL="https://api.fossorial.io/api/v1/versions/olm"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Warnings and errors go to stderr so they still show up when printed from
# inside a $(...) command substitution.
print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Temporary download directory, removed on exit. A fresh mktemp directory
# avoids clobbering (or following a symlink planted at) a fixed /tmp path.
TMP_DIR=""
cleanup() {
    if [ -n "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# Fetch the latest release info (version and asset checksums) from the
# Fossorial API into RELEASE_INFO. Returns 1 if it isn't available.
RELEASE_INFO=""
fetch_release_info() {
    if command -v curl >/dev/null 2>&1; then
        RELEASE_INFO=$(curl -fsSL "$RELEASE_API_URL" 2>/dev/null || true)
    else
        RELEASE_INFO=$(wget -qO- "$RELEASE_API_URL" 2>/dev/null || true)
    fi
    RELEASE_INFO=$(printf '%s' "$RELEASE_INFO" | tr -d '\n\r')
    [ -n "$RELEASE_INFO" ]
}

# latestVersion from RELEASE_INFO, without a leading "v". Parsed without jq.
release_info_version() {
    printf '%s' "$RELEASE_INFO" |
        sed -n 's/.*"latestVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
        sed 's/^v//'
}

# Published sha256 of a release asset from RELEASE_INFO, or nothing.
release_info_digest() {
    asset_re=$(printf '%s' "$1" | sed 's/[][\.*^$/]/\\&/g')
    printf '%s' "$RELEASE_INFO" |
        sed -n "s/.*\"${asset_re}\"[[:space:]]*:[[:space:]]*\"\([0-9a-f]\{64\}\)\".*/\1/p"
}

# sha256 of a file, with whichever tool this system has.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1"
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

# Check a downloaded file against the checksum published for its release
# asset. Exits on a mismatch; warns and carries on when there's no published
# checksum (pinned older version, or the API was unreachable).
verify_checksum() {
    checksum_file="$1"
    checksum_asset="$2"

    checksum_expected=$(release_info_digest "$checksum_asset")
    if [ -z "$checksum_expected" ]; then
        print_warning "No published checksum for ${checksum_asset}; skipping verification."
        return 0
    fi

    checksum_actual=$(sha256_of "$checksum_file" || true)
    if [ -z "$checksum_actual" ]; then
        print_warning "No sha256 tool found (sha256sum, shasum, sha256 or openssl); skipping verification."
        return 0
    fi

    if [ "$checksum_actual" != "$checksum_expected" ]; then
        print_error "Checksum mismatch for ${checksum_asset}!"
        print_error "  expected: ${checksum_expected}"
        print_error "  got:      ${checksum_actual}"
        print_error "The download may be corrupted or tampered with. Nothing was installed."
        exit 1
    fi

    print_status "Checksum verified (sha256 ${checksum_expected})"
}

# Parse command line arguments into REQUESTED_VERSION.
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                if [ -z "$2" ]; then
                    print_error "--version requires a value"
                    exit 1
                fi
                REQUESTED_VERSION="$2"
                shift
                ;;
            --version=*)
                REQUESTED_VERSION="${1#--version=}"
                ;;
            *)
                print_warning "Ignoring unknown argument: $1"
                ;;
        esac
        shift
    done
}

# Set VERSION and BASE_URL for the release to install: the requested version,
# else the latest from the Fossorial API, else GitHub's latest release (which
# is a plain redirect, not a rate-limited GitHub API call). RELEASE_INFO is
# cleared unless it describes the chosen version, so its checksums are only
# ever used for the release they belong to.
resolve_release() {
    latest=""
    if fetch_release_info; then
        latest=$(release_info_version)
    fi

    if [ -n "$REQUESTED_VERSION" ]; then
        VERSION=$(printf '%s' "$REQUESTED_VERSION" | sed 's/^v//')
        case "$VERSION" in
            ""|*[!0-9A-Za-z.+-]*)
                print_error "Invalid version: ${REQUESTED_VERSION}"
                exit 1
                ;;
        esac
        print_status "Requested version: v${VERSION}"
        BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
        if [ "$VERSION" != "$latest" ]; then
            RELEASE_INFO=""
        fi
        return
    fi

    if [ -n "$latest" ]; then
        VERSION="$latest"
        print_status "Latest version: v${VERSION}"
        BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    else
        VERSION=""
        RELEASE_INFO=""
        print_warning "Could not get the latest version from ${RELEASE_API_URL}"
        print_warning "Falling back to the latest release on GitHub"
        BASE_URL="https://github.com/${REPO}/releases/latest/download"
    fi
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
    local temp_file="${TMP_DIR}/olm${exe_suffix}"
    local final_path="${install_dir}/olm${exe_suffix}"
    
    print_status "Downloading olm from ${download_url}"
    
    # Download the binary
    local download_failed=""
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file" || download_failed=1
    else
        wget -q "$download_url" -O "$temp_file" || download_failed=1
    fi
    if [ -n "$download_failed" ] || [ ! -s "$temp_file" ]; then
        print_error "Failed to download ${download_url}"
        print_error "Check that release ${VERSION:-latest} has a ${binary_name} asset."
        exit 1
    fi

    verify_checksum "$temp_file" "$binary_name"
    
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
        if [[ ":${PATH}:" != *":${install_dir}:"* ]]; then
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
    REQUESTED_VERSION="${OLM_VERSION:-}"
    parse_args "$@"

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    print_status "Installing olm..."
    
    resolve_release

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/olm.XXXXXX")
    
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