//go:build !linux

package connector

import "errors"

func processIdentity() (string, error) { return "", errors.New("connector_requires_linux") }
