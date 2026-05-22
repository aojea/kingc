setup_suite() {
    echo "🔨 Building kingc binary..."
    make build
    export KINGC_BIN="./bin/kingc"
}

teardown_suite() {
    echo "🎉 E2E test suite run completed."
}
