#!/usr/bin/env bats

setup() {
    export KINGC_BIN="./bin/kingc"
}

teardown() {
    if [ -n "${CLUSTER_CREATED:-}" ]; then
        echo "🧹 Cleaning up cluster ${CLUSTER_NAME}..."
        run ${KINGC_BIN} delete cluster --name "${CLUSTER_NAME}"
    fi
}

@test "Preflight requirements check" {
    # 1. Run the new kingc preflight subcommand
    run ${KINGC_BIN} preflight
    echo "Preflight Output: $output"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Preflight checks passed" ]]
}

@test "Create cluster, run smoke workload, and delete it" {
    # 1. Generate unique cluster name
    export CLUSTER_NAME="e2e-$(date +%s)"
    export CLUSTER_CREATED="true"

    echo "🚀 Creating cluster ${CLUSTER_NAME}..."
    run ${KINGC_BIN} create cluster --name "${CLUSTER_NAME}" --config ${BATS_TEST_DIRNAME}/config/simple-config.yaml
    echo "Create Output: $output"
    [ "$status" -eq 0 ]

    # 2. Verify Kubeconfig context switches to the correct one
    run kubectl config use-context "kingc-${CLUSTER_NAME}"
    [ "$status" -eq 0 ]

    # 3. Wait for nodes to be ready
    run kubectl wait --for=condition=Ready nodes --all --timeout=300s
    echo "Nodes status: $output"
    [ "$status" -eq 0 ]

    # 4. Run a smoke workload
    run kubectl create deployment smoke-nginx --image=nginx
    [ "$status" -eq 0 ]

    run kubectl rollout status deployment/smoke-nginx --timeout=120s
    echo "Deployment status: $output"
    [ "$status" -eq 0 ]

    # Validate pods are running
    run kubectl get pods -l app=smoke-nginx -o jsonpath="{.items[*].status.phase}"
    [[ "$output" =~ "Running" ]]

    # Clean up deployment
    run kubectl delete deployment smoke-nginx
    [ "$status" -eq 0 ]

    # 5. Delete the cluster
    run ${KINGC_BIN} delete cluster --name "${CLUSTER_NAME}"
    echo "Delete Output: $output"
    [ "$status" -eq 0 ]

    # Unset CLUSTER_CREATED so teardown doesn't run it again
    unset CLUSTER_CREATED
}
