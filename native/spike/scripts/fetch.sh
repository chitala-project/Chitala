#!/usr/bin/env bash
# Fetch the pinned N1 tools (tools.lock) into $N1_CACHE and verify them:
# the Microkit SDK for this host by its sha256 (and, with N1_VERIFY_GPG=1, by its
# signature), and libvmm at its pinned commit. Anything that does not match is
# refused and removed. Prints the environment the build needs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../tools.lock"
CACHE="${N1_CACHE:-$HOME/.cache/chitala-n1}"
mkdir -p "$CACHE"

case "$(uname -s)-$(uname -m)" in
    Linux-aarch64) plat=linux-aarch64 key=linux_aarch64 ;;
    Linux-x86_64) plat=linux-x86-64 key=linux_x86_64 ;;
    Darwin-arm64) plat=macos-aarch64 key=macos_aarch64 ;;
    *) echo "fetch: no Microkit SDK pinned for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac
want_var="MICROKIT_SHA256_$key"
want="${!want_var}"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# --- the Microkit SDK
sdk="$CACHE/microkit-sdk-$MICROKIT_VERSION"
tarball="microkit-sdk-$MICROKIT_VERSION-$plat.tar.gz"
if [ ! -f "$sdk/.verified" ]; then
    url="https://github.com/seL4/microkit/releases/download/$MICROKIT_VERSION/$tarball"
    curl -fsSL --retry 3 -o "$CACHE/$tarball" "$url"
    got="$(sha256 "$CACHE/$tarball")"
    if [ "$got" != "$want" ]; then
        rm -f "$CACHE/$tarball"
        echo "fetch: $tarball has sha256 $got, tools.lock pins $want: refused" >&2
        exit 1
    fi
    if [ "${N1_VERIFY_GPG:-0}" = 1 ]; then
        curl -fsSL --retry 3 -o "$CACHE/$tarball.asc" "$url.asc"
        gnupg="$(mktemp -d)"
        GNUPGHOME="$gnupg" gpg -q --keyserver hkps://keys.openpgp.org --recv-keys "$MICROKIT_GPG_FINGERPRINT"
        if ! GNUPGHOME="$gnupg" gpg -q --status-fd 1 --verify "$CACHE/$tarball.asc" "$CACHE/$tarball" 2>/dev/null \
            | grep -q "VALIDSIG $MICROKIT_GPG_FINGERPRINT"; then
            rm -rf "$gnupg"
            echo "fetch: $tarball is not signed by $MICROKIT_GPG_FINGERPRINT: refused" >&2
            exit 1
        fi
        rm -rf "$gnupg"
        echo "fetch: signature by $MICROKIT_GPG_FINGERPRINT verified" >&2
    fi
    rm -rf "$sdk"
    tar -xzf "$CACHE/$tarball" -C "$CACHE"
    rm -f "$CACHE/$tarball" "$CACHE/$tarball.asc"
    [ -x "$sdk/bin/microkit" ] || { echo "fetch: $tarball has no bin/microkit" >&2; exit 1; }
    echo "$want" > "$sdk/.verified"
fi

# --- libvmm, at its pinned commit (and its submodules)
vmm="$CACHE/libvmm-$LIBVMM_TAG"
if [ ! -f "$vmm/.verified" ]; then
    rm -rf "$vmm"
    git init -q "$vmm"
    git -C "$vmm" fetch -q --depth 1 https://github.com/au-ts/libvmm "$LIBVMM_COMMIT"
    git -C "$vmm" checkout -q FETCH_HEAD
    git -C "$vmm" submodule -q update --init --recursive --depth 1
    got="$(git -C "$vmm" rev-parse HEAD)"
    [ "$got" = "$LIBVMM_COMMIT" ] || { echo "fetch: libvmm is at $got, tools.lock pins $LIBVMM_COMMIT" >&2; exit 1; }
    echo "$LIBVMM_COMMIT" > "$vmm/.verified"
fi

# --- the guest images libvmm's examples boot (N1.2), from trustworthy.systems:
# resumed when a transfer breaks, then checked against their pinned sha256
guests="$CACHE/guests"
mkdir -p "$guests"
for pair in "$LIBVMM_LINUX:$LIBVMM_LINUX_SHA256" "$LIBVMM_INITRD:$LIBVMM_INITRD_SHA256"; do
    name="${pair%%:*}.tar.gz" want="${pair##*:}"
    [ -f "$guests/$name" ] && [ "$(sha256 "$guests/$name")" = "$want" ] && continue
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        curl -fsSL -C - --retry 5 --retry-all-errors -o "$guests/$name" "$LIBVMM_IMAGES/$name" && break
    done
    got="$(sha256 "$guests/$name")"
    if [ "$got" != "$want" ]; then
        rm -f "$guests/$name"
        echo "fetch: $name has sha256 $got, tools.lock pins $want: refused" >&2
        exit 1
    fi
done

echo "MICROKIT_SDK=$sdk"
echo "LIBVMM=$vmm"
echo "GUESTS=$guests"
