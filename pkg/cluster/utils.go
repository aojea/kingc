package cluster

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aojea/kingc/pkg/config"
)

func resolveSubnet(networks []config.NetworkSpec, netName, explicitSubnet string) (string, error) {
	if explicitSubnet != "" {
		return explicitSubnet, nil
	}
	for _, n := range networks {
		if n.Name == netName {
			if len(n.Subnets) == 0 {
				if netName == "default" {
					return "default", nil
				}
				return netName, nil
			}
			if len(n.Subnets) == 1 {
				return n.Subnets[0].Name, nil
			}
			return "", fmt.Errorf("network '%s' has multiple subnets; explicit subnet required", netName)
		}
	}
	return "", fmt.Errorf("network '%s' not found in config", netName)
}

func basename(name string) string {
	return "kingc-cluster-" + name
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "abcdef"
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func untar(dst string, r io.Reader) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer func() {
		_ = gzr.Close()
	}()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case header == nil:
			continue
		}
		target := filepath.Join(dst, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		}
	}
}
