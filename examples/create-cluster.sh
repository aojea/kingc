#!/bin/bash
set -e

# Configuration
CLUSTER_NAME="advanced-demo"
CONFIG_FILE="examples/advanced-config.yaml"
ZONE="us-central1-a"
KINGC_BIN="kingc" # Assumes kingc is in your PATH. If not, set this to ./bin/kingc

echo "🚀 Starting E2E validation for ${CLUSTER_NAME}..."

# 1. Prerequisites Check
echo "🔍 Checking requirements..."

if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud is not installed or not in PATH."
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "❌ Error: kubectl is not installed or not in PATH."
    exit 1
fi

if ! command -v $KINGC_BIN &> /dev/null; then
    echo "❌ Error: '$KINGC_BIN' command not found. Please build/install it first."
    exit 1
fi

# Check GCloud Auth
PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT" ]; then
    echo "❌ Error: No active GCP project found. Run 'gcloud config set project <PROJECT_ID>'."
    exit 1
fi
echo "  ✓ GCP Project: $PROJECT"

# 2. Create Cluster
echo "📦 Creating cluster from ${CONFIG_FILE}..."
$KINGC_BIN create --config "${CONFIG_FILE}"

# 3. Validation
echo "🧪 Validating Cluster..."

# Ensure we are using the correct context
kubectl config use-context "kind-${CLUSTER_NAME}"

# Wait for nodes (kingc creates them, but let's ensure kubectl sees them)
echo "  > Checking Node status..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s
kubectl get nodes -o wide

# Verify Feature Gates & Runtime Config
echo "  > Verifying API Server configuration..."
POD_NAME=$(kubectl get pods -n kube-system -l component=kube-apiserver -o jsonpath="{.items[0].metadata.name}")

# Check for Feature Gate
if kubectl get pod "$POD_NAME" -n kube-system -o yaml | grep -q "UnknownVersionInteroperabilityProxy=true"; then
    echo "  ✓ Feature Gate 'UnknownVersionInteroperabilityProxy' confirmed active."
else
    echo "  ❌ Error: Feature Gate not found in API Server args."
    exit 1
fi

# Check for Runtime Config
if kubectl get pod "$POD_NAME" -n kube-system -o yaml | grep -q "runtime-config=flowcontrol.apiserver.k8s.io/v1beta3=true"; then
    echo "  ✓ Runtime Config 'flowcontrol.apiserver.k8s.io/v1beta3=true' confirmed active."
else
    echo "  ❌ Error: Runtime Config not found in API Server args."
    exit 1
fi

# 4. Cleanup
echo "🧹 Cleaning up..."
$KINGC_BIN delete --name "${CLUSTER_NAME}" --zone "${ZONE}"

echo "✅ E2E Test Passed!"
