#!/usr/bin/env bash
# Setup script for the Homebrew tap repository.
#
# This creates a separate Git repo (homebrew-tap) that Homebrew expects
# at github.com/dalisecurity/homebrew-tap.
#
# Usage:
#   1. Create a repo named "homebrew-tap" under the dalisecurity GitHub org
#   2. Run this script to push the formula
#
# After setup, users install with:
#   brew tap dalisecurity/tap
#   brew install fray

set -euo pipefail

TAP_DIR="$(cd "$(dirname "$0")" && pwd)"
FORMULA="$TAP_DIR/Formula/fray.rb"

echo "=== Fray Homebrew Tap Setup ==="
echo ""
echo "Files ready:"
echo "  Formula: $FORMULA"
echo "  README:  $TAP_DIR/README.md"
echo ""
echo "Next steps:"
echo "  1. Create GitHub repo: github.com/dalisecurity/homebrew-tap"
echo "  2. Push these files:"
echo "     cd $TAP_DIR"
echo "     git init"
echo "     git remote add origin git@github.com:dalisecurity/homebrew-tap.git"
echo "     git add ."
echo "     git commit -m 'feat: add fray formula v3.4.0'"
echo "     git push -u origin main"
echo ""
echo "  3. Test installation:"
echo "     brew tap dalisecurity/tap"
echo "     brew install fray"
echo ""
echo "To update the formula when a new version is released:"
echo "  1. Get the new sdist URL and SHA256 from PyPI"
echo "  2. Update Formula/fray.rb with new url + sha256"
echo "  3. Commit and push to homebrew-tap repo"
