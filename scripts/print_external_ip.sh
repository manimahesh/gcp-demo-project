#!/usr/bin/env bash
# Wait for the LoadBalancer External IP to be assigned to the vuln-backend-svc
# Usage: ./scripts/print_external_ip.sh [NAMESPACE]

NAMESPACE=${1:-default}
SERVICE=vuln-backend-svc
MAX_RETRIES=120   # ~10 minutes if sleep 5s
SLEEP=5

echo "Watching service $SERVICE in namespace '$NAMESPACE' for external IP..."
RETRY=0
while :; do
  IP=$(kubectl get svc $SERVICE -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
  HOSTNAME=$(kubectl get svc $SERVICE -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
  if [[ -n "$IP" ]]; then
    echo "External IP assigned: $IP"
    exit 0
  fi
  if [[ -n "$HOSTNAME" ]]; then
    echo "External hostname assigned: $HOSTNAME"
    exit 0
  fi
  ((RETRY++))
  if [[ $RETRY -gt $MAX_RETRIES ]]; then
    echo "Timed out waiting for external IP/hostname after $((MAX_RETRIES*SLEEP)) seconds." >&2
    kubectl get svc $SERVICE -n $NAMESPACE -o wide
    exit 1
  fi
  sleep $SLEEP
done
