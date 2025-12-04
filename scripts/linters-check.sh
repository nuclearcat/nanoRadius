#!/usr/bin/env bash
# Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

set -euo pipefail

echo "Running cargo fmt..."
cargo fmt --all -- --check

echo "Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Lint checks completed successfully."
