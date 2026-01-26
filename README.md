# kingc (Kubernetes IN Google Cloud)

> **"It's like Kind, but for GCE."**

A lightweight CLI to bootstrap vanilla Kubernetes clusters on Google Compute Engine.

## Directory Layout

```
kingc/
├── cmd/
│   └── kingc/         # The main entrypoint
│       └── main.go
├── pkg/
│   ├── gce/           # GCloud wrapper (The "Shell-out" logic)
│   ├── kubeadm/       # Kubeadm config generation
│   └── templates/     # Embedded templates
├── go.mod
└── README.md
```

## Installation

```bash
go install github.com/aojea/google-cloud-kubernetes/cmd/kingc@latest
```

## Usage

```bash
kingc
```
