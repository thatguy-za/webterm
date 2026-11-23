#!/usr/bin/env bash
# Opens real VNC servers (TigerVNC) through WebTerm in headless Chromium, to check the logins work end to end.
# Screenshots land in tests/vnc/out. Needs Docker.
set -euo pipefail
cd "$(dirname "$0")/../.."

NET=webterm-vnc-test
PLAYWRIGHT=mcr.microsoft.com/playwright:v1.64.1-noble
cleanup() { docker rm -f vnctest-app vnctest-vnc vnctest-wayvnc >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker build -q -t webterm:ui-test .
docker build -q -t webterm-test-tigervnc -f tests/vnc/tigervnc.Dockerfile tests/vnc
docker build -q -t webterm-test-wayvnc -f tests/vnc/wayvnc.Dockerfile tests/vnc
docker network create "$NET" >/dev/null
docker run -d --name vnctest-vnc --network "$NET" --network-alias tigervnc webterm-test-tigervnc >/dev/null
docker run -d --name vnctest-wayvnc --network "$NET" --network-alias wayvnc webterm-test-wayvnc >/dev/null
docker run -d --name vnctest-app --network "$NET" --network-alias webterm webterm:ui-test >/dev/null
sleep 14

mkdir -p tests/vnc/out && rm -f tests/vnc/out/*.png
docker run --rm --network "$NET" -e OUT=/work/out -v "$PWD/tests/vnc":/work "$PLAYWRIGHT" \
  sh -c 'cd /tmp && npm i playwright@1.64.1 --silent >/dev/null 2>&1; cp /work/e2e.js /tmp/ && node /tmp/e2e.js'
