REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin
KIND_CLOUD_BINARY_NAME?=kingc

# go1.9+ can autodetect GOROOT, but if some other tool sets it ...
GOROOT:=
# enable modules
GO111MODULE=on
# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED


build:
	go build -v -o "$(OUT_DIR)/$(KIND_CLOUD_BINARY_NAME)" $(KIND_CLOUD_BUILD_FLAGS) cmd/kingc/main.go

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...

# code linters
lint:
	hack/lint.sh

update:
	go mod tidy

# kube-apiserver image
KUBE_APISERVER_IMAGE?=kingc-apiserver
KUBE_APISERVER_TAG?=latest
KUBE_VERSION?=v1.35.0
ETCD_VERSION?=v3.5.12

image-kubeapiserver:
	docker build \
		--build-arg KUBE_VERSION=$(KUBE_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		-t $(KUBE_APISERVER_IMAGE):$(KUBE_APISERVER_TAG) \
		kubeapiserver/
