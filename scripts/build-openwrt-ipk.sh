#!/bin/bash
# Build fwmon and package it as an OpenWrt IPK.
#
# Run on Linux / WSL / macOS. Cross-compilation uses Docker (rust-musl-cross)
# when available; otherwise falls back to a local Rust toolchain with the
# aarch64-unknown-linux-musl target installed.
#
# Usage:
#   ARCH=aarch64_cortex-a53 ./scripts/build-openwrt-ipk.sh      # default (ipq60xx)
#   ARCH=x86_64 ./scripts/build-openwrt-ipk.sh                  # for local testing
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

APP_NAME="fwmon"
OPENWRT_ARCH="${ARCH:-aarch64_cortex-a53}"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n1)"
VERSION="${VERSION:-0.1.0}"

# Map OpenWrt arch -> Rust musl target.
case "${OPENWRT_ARCH}" in
	x86_64)                       RUST_TARGET="x86_64-unknown-linux-musl" ;;
	aarch64_cortex-a53|aarch64_cortex-a72|aarch64_generic)
	                              RUST_TARGET="aarch64-unknown-linux-musl" ;;
	arm_cortex-a7_neon-vfpv4|arm_cortex-a5_vfpv4|arm_cortex-a15_neon-vfpv4)
	                              RUST_TARGET="armv7-unknown-linux-musleabihf" ;;
	*)                            RUST_TARGET="aarch64-unknown-linux-musl" ;;
esac

OUT_DIR="${ROOT_DIR}/dist"
STAGE_DIR="${OUT_DIR}/ipk-${OPENWRT_ARCH}"
IPK_NAME="${APP_NAME}_${VERSION}_${OPENWRT_ARCH}.ipk"

log() { echo "[build-openwrt] $*"; }

build_binary() {
	if command -v docker >/dev/null 2>&1; then
		local image="messense/rust-musl-cross:${RUST_TARGET%%-unknown*}-musl"
		log "cross-compiling via Docker (${image}) -> ${RUST_TARGET}"
		docker run --rm -v "${ROOT_DIR}":/src -w /src "${image}" \
			cargo build --release --target "${RUST_TARGET}" --locked || \
		docker run --rm -v "${ROOT_DIR}":/src -w /src "${image}" \
			cargo build --release --target "${RUST_TARGET}"
	else
		log "Docker not found; using local cargo (target ${RUST_TARGET})"
		cargo build --release --target "${RUST_TARGET}"
	fi
}

main() {
	log "building ${APP_NAME} ${VERSION} for ${OPENWRT_ARCH} (${RUST_TARGET})"
	build_binary

	local bin="${ROOT_DIR}/target/${RUST_TARGET}/release/${APP_NAME}"
	if [ ! -x "${bin}" ]; then
		echo "[build-openwrt] ERROR: binary not found at ${bin}" >&2
		exit 1
	fi

	rm -rf "${STAGE_DIR}"
	mkdir -p "${STAGE_DIR}/data" "${STAGE_DIR}/control"

	# data filesystem tree
	cp -a "${ROOT_DIR}/openwrt/etc"  "${STAGE_DIR}/data/"
	cp -a "${ROOT_DIR}/openwrt/usr"  "${STAGE_DIR}/data/"
	cp -a "${ROOT_DIR}/openwrt/www"  "${STAGE_DIR}/data/"
	mkdir -p "${STAGE_DIR}/data/usr/sbin"
	cp "${bin}" "${STAGE_DIR}/data/usr/sbin/${APP_NAME}"
	chmod 755 "${STAGE_DIR}/data/usr/sbin/${APP_NAME}"
	chmod 755 "${STAGE_DIR}/data/etc/init.d/${APP_NAME}" \
	          "${STAGE_DIR}/data/usr/lib/${APP_NAME}/block.sh" \
	          "${STAGE_DIR}/data/usr/lib/${APP_NAME}/unblock.sh"

	# control metadata
	cp "${ROOT_DIR}/openwrt/CONTROL/." "${STAGE_DIR}/control/"
	sed -i "s/^Architecture:.*/Architecture: ${OPENWRT_ARCH}/" "${STAGE_DIR}/control/control"
	sed -i "s/^Version:.*/Version: ${VERSION}-1/" "${STAGE_DIR}/control/control"
	chmod 755 "${STAGE_DIR}/control/postinst" "${STAGE_DIR}/control/prerm" "${STAGE_DIR}/control/postrm"

	# archives
	tar --owner=0 --group=0 --numeric-owner --sort=name \
	    -C "${STAGE_DIR}/data"    -czf "${STAGE_DIR}/data.tar.gz"    .
	tar --owner=0 --group=0 --numeric-owner --sort=name \
	    -C "${STAGE_DIR}/control" -czf "${STAGE_DIR}/control.tar.gz" .
	printf '2.0\n' > "${STAGE_DIR}/debian-binary"

	# package: ar-based ipk (fall back to tar container if ar is missing)
	local ipk="${OUT_DIR}/${IPK_NAME}"
	rm -f "${ipk}"
	if command -v ar >/dev/null 2>&1; then
		( cd "${STAGE_DIR}" && ar r "${ipk}" debian-binary control.tar.gz data.tar.gz )
	else
		( cd "${STAGE_DIR}" && tar -czf "${ipk}" debian-binary control.tar.gz data.tar.gz )
	fi

	log "created ${ipk}"
	( cd "${OUT_DIR}" && sha256sum "${IPK_NAME}" > SHA256SUMS 2>/dev/null || shasum -a 256 "${IPK_NAME}" > SHA256SUMS )
	log "checksum: $(cat "${OUT_DIR}/SHA256SUMS")"
}

main "$@"
