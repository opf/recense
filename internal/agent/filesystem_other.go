//go:build !linux

package agent

import "fmt"

func containerFilesystem(_ string, _ int) (string, []string, func() error, error) {
	return "", nil, nil, fmt.Errorf("container filesystem scanning requires Linux")
}
