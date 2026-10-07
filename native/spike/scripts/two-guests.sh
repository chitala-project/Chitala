# shellcheck shell=bash
# shellcheck disable=SC2034 # the patterns are for the scripts that source this
# N1.4 and N1.5: build the two-guests system (sel4/two-guests) and boot it on
# QEMU. Sourced by run-n1.4.sh and run-n1.5.sh, which have set HERE, REPO and
# the SDK's environment (fetch.sh, build-sdk.sh).
#
#   two_guests_boot NAME "ADAPTER ARGS"
#
# builds in $N1_BUILD/NAME with the images native/run.sh --build-only last
# built (two_guests_build), boots until the core's kernel shuts down or
# N1_BOOT_SECONDS pass (two_guests_run [LOG]), and leaves the log, cleaned,
# in $clean. Then `expect` checks one claim.
#
# The log is one UART. The core's guest writes to it directly; the adapter's
# guest has no UART, and its VMM writes each of its lines behind "ADAPTER| "
# (N1.5a). So a pattern for a line of the core's is anchored at the start of
# the line, and no line of the adapter's can match it. A line of the
# adapter's that lands in the middle of one of the core's is moved apart, and
# the core's line joined again (scripts/core-lines.py), so a cut line does not
# fail a check.

two_guests_boot() {
    two_guests_build "$1" "$2"
    two_guests_run
}

two_guests_build() {
    local name="$1" adapter_args="$2"
    local images="${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release"
    for image in chitala-native chitala-native-adapter; do
        if [ ! -f "$images/$image" ]; then
            echo "$name: no $image in $images: build both with native/run.sh --build-only" >&2
            exit 1
        fi
    done
    BUILD="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/$name"
    rm -rf "$BUILD" && mkdir -p "$BUILD"
    cp -R "$LIBVMM" "$BUILD/libvmm"
    for p in "$HERE"/sdk/libvmm-*.patch; do
        git -C "$BUILD/libvmm" apply "$p"
    done
    python3 "$HERE/scripts/core-lines.py" --self-test
    make -s -C "$HERE/sel4/two-guests" BUILD_DIR="$BUILD/out" MICROKIT_SDK="$MICROKIT_SDK" LIBVMM="$BUILD/libvmm" \
        LOADER_ELF="$HERMIT_LOADER" CORE_ELF="$images/chitala-native" ADAPTER_ELF="$images/chitala-native-adapter" \
        ADAPTER_ARGS="$adapter_args"
}

two_guests_run() { # [log]
    log="${1:-$BUILD/boot.log}"
    qemu-system-aarch64 \
        -machine virt,virtualization=on,gic-version=3 -cpu neoverse-n2 -m size=2G \
        -nographic -serial mon:stdio -nic none \
        -device loader,file="$BUILD/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
    local qemu=$!
    # the core runs its scenario, says what it checked, and stops. Only the
    # core's kernel ends the run: a line of the adapter's that says the same
    # is behind its prefix
    local deadline=$((SECONDS + ${N1_BOOT_SECONDS:-900}))
    while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ] &&
        ! grep -a "Shutting down system" "$log" | grep -qv "^ADAPTER|"; do
        sleep 0.5
    done
    kill "$qemu" 2>/dev/null || true
    wait "$qemu" 2>/dev/null || true

    clean="${log%.log}.txt"
    tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' | python3 "$HERE/scripts/core-lines.py" >"$clean"
}

fail=0
expect() { # what, extended regular expression
    if grep -Eq "$2" "$clean"; then echo "ok    $1"; else echo "FAIL  $1: no /$2/"; fail=1; fi
}
reject() { # what, extended regular expression that must not match
    if grep -Eq "$2" "$clean"; then echo "FAIL  $1: /$2/ matches"; fail=1; else echo "ok    $1"; fi
}
count() { # what, extended regular expression, how many
    local n
    n=$(grep -Ec "$2" "$clean" || true)
    if [ "${n:-0}" = "$3" ]; then echo "ok    $1: $3"; else echo "FAIL  $1: ${n:-0}, not $3"; fail=1; fi
}
# the lines of the core's that N1.4 and N1.5 check, anchored
CORE_RECEIPT='^    identity .*→ ALLOW +executed, device reports'
CORE_UNKNOWN='^    identity .*→ UNKNOWN +X_EXECUTION_UNKNOWN'
CORE_VERDICT='^\[halt\] +14/14 decisions as expected · CHITALA NATIVE OK$'
CORE_AUDIT='^\[audit\] +[0-9]+ records · hash chain ✓'
CORE_ENTROPY='^\[boot\] +platform native-hermit · entropy: CPU RNDR \(FEAT_RNG\)'
CORE_EXIT='^exit status 0$'
two_guests_finish() { # name
    if [ "$fail" != 0 ]; then
        echo "$1 FAILED (boot log: $log)"
        # what a VMM could not handle, with the fault's first lines
        grep -a -A6 "|ERROR" "$clean" | head -80 || true
        echo "…"
        grep -v "^LDR|INFO: region\|copying region" "$clean" | tail -60
        exit 1
    fi
    echo "$1: passed"
}
