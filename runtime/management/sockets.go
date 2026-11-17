// Package management provides the protected, consumer-scoped machine operation transport.
package management

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Sockets struct {
	lock      *os.File
	servers   []*http.Server
	listeners []net.Listener
	cancel    context.CancelFunc
}

// Listen acquires the publisher lock before opening the fixed consumer endpoints.
func Listen(root string, connector, apps, orchestrator, telemetry http.Handler) (*Sockets, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("management_socket_directory")
	}
	for path := root; path != "/"; path = filepath.Dir(path) {
		if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return nil, errors.New("management_socket_directory")
		} else if err != nil && !os.IsNotExist(err) {
			return nil, errors.New("management_socket_directory")
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(root, ".lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("management_lock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Sockets{lock: os.NewFile(uintptr(fd), "management-lock"), cancel: cancel}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		s.Close()
		return nil, errors.New("management_already_running")
	}
	consumers := []struct {
		name    string
		handler http.Handler
	}{{"connector", connector}, {"apps", apps}, {"orchestrator", orchestrator}, {"telemetry", telemetry}}
	for _, consumer := range consumers {
		directory := filepath.Join(root, consumer.name)
		info, err := os.Lstat(directory)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			s.Close()
			return nil, errors.New("management_socket_directory")
		}
		if err = os.MkdirAll(directory, 0700); err != nil {
			s.Close()
			return nil, err
		}
		if err = os.Chmod(directory, 0700); err != nil {
			s.Close()
			return nil, err
		}
		path := filepath.Join(directory, "control.sock")
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				s.Close()
				return nil, errors.New("management_socket_occupied")
			}
			if err = os.Remove(path); err != nil {
				s.Close()
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			s.Close()
			return nil, err
		}
		listener, err := net.Listen("unix", path)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.listeners = append(s.listeners, listener)
		if err = os.Chmod(path, 0600); err != nil {
			s.Close()
			return nil, err
		}
		s.servers = append(s.servers, &http.Server{Handler: consumer.handler, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192})
	}
	return s, nil
}

func (s *Sockets) Run(ctx context.Context) error {
	done := make(chan error, len(s.servers))
	for i, server := range s.servers {
		go func() { done <- server.Serve(s.listeners[i]) }()
	}
	select {
	case <-ctx.Done():
		return nil
	case <-done:
		return errors.New("management_socket_unavailable")
	}
}

func (s *Sockets) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, server := range s.servers {
		// Keep the publisher lock until every credential handler has stopped writing.
		_ = server.Shutdown(context.Background())
	}
	for _, listener := range s.listeners {
		_ = listener.Close()
	}
	if s.lock != nil {
		_ = s.lock.Close()
	}
}
