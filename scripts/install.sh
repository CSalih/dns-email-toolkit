#!/bin/sh
#
# Base script from Deno. Credits goes to Deno Team :clap:
# See: https://github.com/denoland/deno_install/blob/101a27a406847f628790525b8df10b326ce858ef/install.sh

set -e

if ! command -v unzip >/dev/null; then
	echo "Error: unzip is required to install DNS Email Toolkit." 1>&2
	exit 1
fi

if [ "$OS" = "Windows_NT" ]; then
	target="x86_64-pc-windows-msvc"
else
	case $(uname -sm) in
	"Darwin x86_64") target="x86_64-apple-darwin" ;;
	"Darwin arm64") target="aarch64-apple-darwin" ;;
	"Linux aarch64")
		echo "Error: Official DNS Email Toolkit builds for Linux aarch64 are not available." 1>&2
		exit 1
		;;
	*) target="x86_64-unknown-linux-gnu" ;;
	esac
fi

if [ $# -eq 0 ]; then
	deno_uri="https://github.com/CSalih/dns-email-toolkit/releases/latest/download/det-${target}.zip"
else
	deno_uri="https://github.com/CSalih/dns-email-toolkit/releases/download/${1}/det-${target}.zip"
fi

install_dir="${INSTALL_DIR:-$HOME/.det}"
bin_dir="$install_dir/bin"
exe="$bin_dir/det"

if [ ! -d "$bin_dir" ]; then
	mkdir -p "$bin_dir"
fi

curl --fail --location --progress-bar --output "$exe.zip" "$deno_uri"
unzip -d "$bin_dir" -o "$exe.zip"
chmod +x "$exe"
rm "$exe.zip"

echo "DNS Email Toolkit was installed successfully to $exe"
if command -v det >/dev/null; then
	echo "Run 'det --help' to get started"
else
	case $SHELL in
	/bin/zsh) shell_profile=".zshrc" ;;
	*) shell_profile=".bashrc" ;;
	esac
	echo "Manually add the directory to your \$HOME/$shell_profile (or similar)"
	echo "  export PATH=\"\$bin_dir:\$PATH\""
	echo "Run '$exe --help' to get started"
fi
echo