#!/bin/sh
set -eu

usage() {
    printf '%s\n' 'Usage: sh install.sh [--prepare-only]' \
        'Prepare the pinned upstream zapret2 Linux distribution and run its interactive installer.' \
        'Pass --prepare-only to select the binaries without making system changes.'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
    ''|--prepare-only) [ "$#" -le 1 ] || { usage >&2; exit 2; } ;;
    *) usage >&2; exit 2 ;;
esac

if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'This installer requires Linux.' >&2
    exit 1
fi

for program in curl tar sha256sum; do
    command -v "$program" >/dev/null 2>&1 || {
        printf 'Required program not found: %s\n' "$program" >&2
        exit 1
    }
done

version=v1.0.7
name="zapret2-$version"
digest=547a5dce3f4820721a425680ea3f7f3971b7e9c772b8c795dd2d623148da0928
destination="$PWD/$name"
if [ -e "$destination" ] || [ -L "$destination" ]; then
    printf 'Directory already exists: %s\n' "$destination" >&2
    exit 1
fi

work=$(mktemp -d "$PWD/.zapret-rust.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM

curl --fail --silent --show-error --location --retry 2 --connect-timeout 15 \
    --max-time 180 --proto '=https' --proto-redir '=https' \
    "https://github.com/bol-van/zapret2/releases/download/$version/$name.tar.gz" \
    --output "$work/upstream.tar.gz"
printf '%s  %s\n' "$digest" "$work/upstream.tar.gz" | sha256sum --check
tar --extract --gzip --file "$work/upstream.tar.gz" --directory "$work" \
    --no-same-owner --no-same-permissions
mv -T --no-clobber -- "$work/$name" "$destination"
if [ -d "$work/$name" ]; then
    printf 'Directory already exists: %s\n' "$destination" >&2
    exit 1
fi

if [ "${1-}" = --prepare-only ]; then
    ZAPRET_BASE="$destination" sh "$destination/install_bin.sh"
    printf 'Prepared %s\n' "$destination"
    exit 0
fi

sh "$destination/install_easy.sh"
