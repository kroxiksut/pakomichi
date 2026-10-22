#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build the R-006 TEST ONLY DEB fixtures in the Debian 12 builder
# (pakomichi-r001-build-deb). Needs binutils and dpkg-dev; no compiler.
#
#   sampleapp-elf    1.0-1 amd64: /usr/bin/sampleapp-elf, a static ELF built
#                    from the assembly below; it prints one line and exits 0.
#                    It is not signed for the Astra Linux closed environment.
#   sampleapp-script 1.0-1 all:   no executable, a postinst that writes
#                    /var/lib/sampleapp-script/postinst-ran.
#
# Usage: build-deb.sh OUTPUT_DIR
set -euo pipefail

out="${1:?usage: build-deb.sh OUTPUT_DIR}"
export SOURCE_DATE_EPOCH=1760832000
work="$(mktemp -d /tmp/pakomichi-r006-build.XXXXXXXX)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

control() {
    # name version arch description
    cat <<EOF
Package: $1
Version: $2
Architecture: $3
Maintainer: Pakomichi R-006 TEST ONLY <r006@pakomichi.test>
Section: misc
Priority: optional
Description: Pakomichi R-006 TEST ONLY fixture
 $4
EOF
}

# sampleapp-elf: write(1, msg, len); exit(0)
cat > "$work/elf.s" <<'EOF'
    .globl _start
    .section .rodata
msg: .ascii "sampleapp-elf: ran\n"
len = . - msg
    .text
_start:
    mov $1, %eax
    mov $1, %edi
    lea msg(%rip), %rsi
    mov $len, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
EOF
as -o "$work/elf.o" "$work/elf.s"
ld -s -o "$work/sampleapp-elf" "$work/elf.o"

root="$work/elf-root"
install -D -m 0755 "$work/sampleapp-elf" "$root/usr/bin/sampleapp-elf"
install -d "$root/DEBIAN"
control sampleapp-elf 1.0-1 amd64 "Unsigned static ELF that prints one line." > "$root/DEBIAN/control"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out/sampleapp-elf_1.0-1_amd64.deb"

root="$work/script-root"
install -D -m 0644 /dev/null "$root/usr/share/doc/sampleapp-script/README"
echo "Pakomichi R-006 TEST ONLY" > "$root/usr/share/doc/sampleapp-script/README"
install -d "$root/DEBIAN"
control sampleapp-script 1.0-1 all "Package whose postinst writes a marker file." > "$root/DEBIAN/control"
cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
mkdir -p /var/lib/sampleapp-script
echo "postinst-ran $1" > /var/lib/sampleapp-script/postinst-ran
EOF
cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ] || [ "$1" = remove ]; then rm -rf /var/lib/sampleapp-script; fi
EOF
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/postrm"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out/sampleapp-script_1.0-1_all.deb"

cd "$out" && sha256sum sampleapp-elf_1.0-1_amd64.deb sampleapp-script_1.0-1_all.deb | tee SHA256SUMS
