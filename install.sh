#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -eu

readonly JOERN_VERSION=$(<joern-version)

if [ "$(uname)" = 'Darwin' ]; then
  # get script location
  # https://unix.stackexchange.com/a/96238
  if [ "${BASH_SOURCE:-x}" != 'x' ]; then
    this_script=$BASH_SOURCE
  elif [ "${ZSH_VERSION:-x}" != 'x' ]; then
    setopt function_argzero
    this_script=$0
  elif eval '[[ -n ${.sh.file} ]]' 2>/dev/null; then
    eval 'this_script=${.sh.file}'
  else
    echo 1>&2 "Unsupported shell. Please use bash, ksh93 or zsh."
    exit 2
  fi
  relative_directory=$(dirname "$this_script")
  SCRIPT_ABS_DIR=$(cd "$relative_directory" && pwd)
else
  SCRIPT_ABS_PATH=$(readlink -f "$0")
  SCRIPT_ABS_DIR=$(dirname "$SCRIPT_ABS_PATH")
fi

# Check required tools are installed.
check_installed() {
  if ! type "$1" > /dev/null; then
    echo "Please ensure you have $1 installed."
    exit 1
  fi
}

JOERN_INSTALL="$SCRIPT_ABS_DIR/joern-inst"

echo "Examining Joern installation..."

INSTALL_JOERN=true
EXISTING_JOERN_PATH=""

# Check if joern is already installed in the system or locally
if command -v joern &> /dev/null; then
    EXISTING_JOERN_PATH=$(dirname $(dirname $(readlink -f $(command -v joern))))
    echo "Found existing Joern installation at: $EXISTING_JOERN_PATH"
elif [ -d "${JOERN_INSTALL}" ]; then
    EXISTING_JOERN_PATH="${JOERN_INSTALL}"
    echo "Found existing local Joern installation at: $EXISTING_JOERN_PATH"
fi

if [ -n "$EXISTING_JOERN_PATH" ]; then
    echo "Joern is already installed. What would you like to do?"
    echo "  [1] Re-download and install Joern (v$JOERN_VERSION) locally"
    echo "  [2] Use existing installation"
    read -p "Enter your choice (1/2): " choice
    case "$choice" in
        1)
            INSTALL_JOERN=true
            ;;
        2)
            INSTALL_JOERN=false
            if [ "$EXISTING_JOERN_PATH" != "$JOERN_INSTALL" ]; then
                 echo "Warning: Using system Joern at $EXISTING_JOERN_PATH. Ensure you have write permissions to install plugins there."
                 JOERN_INSTALL="$EXISTING_JOERN_PATH"
            fi
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
fi

if [ "$INSTALL_JOERN" = true ]; then
    # if [ -d "${JOERN_INSTALL}" ]; then
    #     echo "Removing existing local installation..."
    #     rm -rf "${JOERN_INSTALL}"
    # fi
    echo "Installing..."
    check_installed "curl"

    # Fetch installer
    echo "https://github.com/ShiftLeftSecurity/joern/releases/download/v$JOERN_VERSION/joern-install.sh"
    curl -L "https://github.com/ShiftLeftSecurity/joern/releases/download/v$JOERN_VERSION/joern-install.sh" -o "$SCRIPT_ABS_DIR/joern-install.sh"

    # Install into `joern-inst`
    chmod +x $SCRIPT_ABS_DIR/joern-install.sh
    $SCRIPT_ABS_DIR/joern-install.sh --install-dir="$SCRIPT_ABS_DIR/joern-inst" --version=v$JOERN_VERSION --without-plugins
    rm $SCRIPT_ABS_DIR/joern-install.sh
fi

echo "Building and installing plugin - incl. domain classes for schema extension..."
pushd $SCRIPT_ABS_DIR
sbt createDistribution replaceDomainClassesInJoern
popd

pushd "${JOERN_INSTALL}/joern-cli"
  ./joern --remove-plugin plugin || true
  ./joern --add-plugin $SCRIPT_ABS_DIR/plugin.zip
popd

echo "All done! Joern and this plugin are ready to use in ${JOERN_INSTALL}. Example usage:"
echo ""
echo "$ cd ${JOERN_INSTALL}/joern-cli"
echo "$ ./joern"
echo "joern> importCpg(\"/path/to/cpg.bin\")"
echo "joern> opts.traceextension.pathToTrace = \"/path/to/trace.json\""
echo "joern> run.traceextension"
echo "joern> cpg.method.has(\"TRACE_DEPTH\").name.l"
echo "joern> opts.autodetect.outputPath = \"/path/to/VulReport.txt\""
echo "joern> run.autodetect"
