#!/bin/bash
set -e

# Start etcd
# We use a unix socket for client communication to simplify security.
# Data directory should be mounted at /data for persistence.
echo "Starting etcd..."
mkdir -p /var/run/etcd
/usr/local/bin/etcd \
  --data-dir=/data/etcd \
  --listen-client-urls=unix:///var/run/etcd/etcd.sock \
  --advertise-client-urls=http://localhost:2379 \
  --log-level=warn &
ETCD_PID=$!

# Wait for etcd to be available with 5 minute timeout
echo "Waiting for etcd to be ready..."
START_TIME=$(date +%s)
TIMEOUT=300

while true; do
  if /usr/local/bin/etcdctl --endpoints=unix:///var/run/etcd/etcd.sock endpoint health &>/dev/null; then
    echo "etcd is ready."
    break
  fi

  CURRENT_TIME=$(date +%s)
  ELAPSED=$((CURRENT_TIME - START_TIME))
  
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "Error: Timed out waiting for etcd to be ready after ${TIMEOUT} seconds."
    kill $ETCD_PID
    exit 1
  fi
  
  sleep 1
done

echo "Starting kube-apiserver..."
exec /usr/local/bin/kube-apiserver \
  --etcd-servers=unix:///var/run/etcd/etcd.sock \
  "$@"
