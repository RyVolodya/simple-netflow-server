#!/usr/bin/env bash
set -euo pipefail
echo "== v0.8.10 Dashboard period selector and version checks =="
grep -q 'APP_VERSION: 0.8.10' docker-compose.yml
grep -q 'setting-value">0.8.10<' frontend/index.html
grep -q "x.version!=='0.8.10'" frontend/index.html
grep -q 'v0.8.10: responsive safety' frontend/index.html
grep -q '@media(max-width:380px)' frontend/index.html
grep -q '@media(min-width:561px) and (max-width:950px)' frontend/index.html
echo "OK"

grep -q '#dashboard .dashboard-period' frontend/index.html
