#!/bin/sh
set -eu
echo "== v0.8.7 version synchronization =="
grep -q 'APP_VERSION: 0.8.7' docker-compose.yml
grep -q 'setting-value">0.8.7<' frontend/index.html
grep -q "x.version!=='0.8.7'" frontend/index.html
echo "Version synchronization: OK"
