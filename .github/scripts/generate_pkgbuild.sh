#!/usr/bin/env bash
set -euo pipefail

mkdir -p pkg/arch
cat > pkg/arch/PKGBUILD <<'PKG'
pkgname=velocity
pkgver=${1:-0.1.0}
pkgrel=1
arch=('x86_64' 'aarch64')
url="https://github.com/${GITHUB_REPOSITORY}"
license=('MIT')
depends=('openssl' 'ca-certificates')
makedepends=('rust' 'cargo')
source=("https://github.com/${GITHUB_REPOSITORY}/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$srcdir/${GITHUB_REPOSITORY##*/}-$pkgver"
  cargo build --release --target x86_64-unknown-linux-gnu
}

package() {
  cd "$srcdir/${GITHUB_REPOSITORY##*/}-$pkgver"
  install -Dm755 "target/x86_64-unknown-linux-gnu/release/velocity" "$pkgdir/usr/bin/velocity"
  install -Dm644 "docs/velocity.service" "$pkgdir/usr/lib/systemd/system/velocity.service" || true
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/velocity/README.md"
}

PKG

echo "Generating .SRCINFO"
mksrcinfo -P pkg/arch || true
echo "Wrote pkg/arch/PKGBUILD and pkg/arch/.SRCINFO"
