package httpsource

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/transport"
)

// Compare verified component inputs, without borrowing readiness from another workload.
func (s *Source) componentUnchanged(name, previous, current string) bool {
	paths := map[string]string{"livepeer-node": "system/node/", "livepeer-connector": "system/connector/", "livepeer-upgrade-plan": "upgrade-plan/"}
	prefix := paths[name]
	if prefix == "" {
		return false
	}
	read := func(digest string) ([]byte, string, string, error) {
		data, err := s.Store.Get(digest)
		if err != nil {
			return nil, "", "", err
		}
		files, err := artifact.Read(data)
		if err != nil {
			return nil, "", "", err
		}
		m, err := transport.ReadMetadata(files["runtime.json"])
		if err != nil {
			return nil, "", "", err
		}
		selected := map[string][]byte{}
		for path, b := range files {
			if strings.HasPrefix(path, prefix) {
				selected[path] = b
			}
		}
		if len(selected) == 0 {
			return nil, "", "", errors.New("component_input_missing")
		}
		b, err := json.Marshal(selected)
		return b, m.NodeID, m.Epoch, err
	}
	a, an, ae, errA := read(previous)
	b, bn, be, errB := read(current)
	return errA == nil && errB == nil && an == bn && ae == be && bytes.Equal(a, b)
}
