#!/usr/bin/env bash
# End-to-end test on a real Nitro Sandbox node.
# Required: GUESTWATCH_IMAGE. Optional: NAMESPACE (default), RUNTIME_CLASS
# (isolated-sandbox), KUBECTL_CONTEXT. Exits non-zero if any check fails.
set -euo pipefail
: "${GUESTWATCH_IMAGE:?set GUESTWATCH_IMAGE}"
export RUNTIME_CLASS="${RUNTIME_CLASS:-isolated-sandbox}"
NS="${NAMESPACE:-default}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
mkdir -p "$OUT"
k() { kubectl ${KUBECTL_CONTEXT:+--context "$KUBECTL_CONTEXT"} -n "$NS" "$@"; }
POD=guestwatch-e2e
# The Pod is deleted on exit; set KEEP=1 to keep it for inspection.
cleanup() { [ -n "${KEEP:-}" ] || k delete pod "$POD" --ignore-not-found --wait=false >/dev/null; }
trap cleanup EXIT

k delete pod "$POD" --ignore-not-found --wait=true >/dev/null
envsubst < "$HERE/pod.yaml" | k apply -f - >/dev/null
k wait --for=condition=Ready "pod/$POD" --timeout=300s >/dev/null
until k logs "$POD" -c guestwatch 2>/dev/null | grep -q '"agent_start"'; do sleep 1; done

ids() { k get pod "$POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}={.containerID}{"\n"}{end}' | sed 's#containerd://##'; }
ids > "$OUT/ids-before.txt"

echo "[1/3] generating activity in the workload containers"
k exec "$POD" -c workload -- bash -c '
  cp /usr/bin/curl /tmp/fastcurl && /tmp/fastcurl --version >/dev/null
  curl -s -m 5 -o /dev/null http://example.com || true
  for i in $(seq 1 500); do echo x > /dev/udp/192.0.2.20/9999; done
  mkdir -p /tmp/c/d && cp /usr/bin/true /tmp/c/d/y
  echo hi > /tmp/abs/f
  curl -s -m 3 -o /dev/null "http://[::ffff:93.184.216.34]/" || true
  bash -c "sleep 2" long-argument "$(head -c 6000 /dev/zero | tr "\0" a)"
'
k exec "$POD" -c workload-root -- sh -c '
  cp /usr/bin/true /usr/local/bin/evil
  mkdir -p /tmp/s && mv /tmp/s /usr/local/bin/s && sleep 1 && echo x > /usr/local/bin/s/f
'

echo "[2/3] restarting the workload container"
k exec "$POD" -c workload -- sh -c 'kill "$(cat /tmp/main.pid)"' || true
until [ "$(k get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="workload")].restartCount}')" = 1 ] \
  && k exec "$POD" -c workload -- true 2>/dev/null; do sleep 2; done
sleep 3
k exec "$POD" -c workload -- sh -c 'echo after > /tmp/after_restart'
ids > "$OUT/ids-after.txt"

echo "[3/3] collecting events and checking"
sleep 15
k logs "$POD" -c guestwatch > "$OUT/events.jsonl"
python3 "$HERE/check.py" "$OUT/events.jsonl" "$OUT/ids-before.txt" "$OUT/ids-after.txt"
