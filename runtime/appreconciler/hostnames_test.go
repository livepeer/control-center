package appreconciler

import (
	"testing"
	"time"
)

func TestReservedHostnamesCannotBecomeAcceptedAppIdentities(t *testing.T) {
	for _, id := range []string{"api", "discovery", "api-aaaaaaa", "discovery-aaaaaaa"} {
		t.Run(id, func(t *testing.T) {
			c, _, cluster, owner, _, _ := fixtureController(t)
			registerApps(t, c, cluster)
			request := owner.Accepted()
			// Treat one entry as a first registration, so rejection cannot come
			// merely from changing an already-bound app identity.
			if err := c.Journal.Update(func(s *State) error { s.Instances[request.Entries[0].InstanceID].AppID = ""; return nil }); err != nil {
				t.Fatal(err)
			}
			before := c.Journal.View()
			sequence, err := c.Journal.Reserve(request.Hash)
			if err != nil {
				t.Fatal(err)
			}
			observation := Observation{Epoch: request.Epoch, Hash: request.Hash, RunnerID: request.Identity.RunnerID, PreviousCredential: before.Identity.Credential, ReservedSequence: sequence, Sequence: sequence, At: c.now(), TTL: 30 * time.Second, Entries: request.Entries}
			for _, entry := range request.Entries {
				observation.Apps = append(observation.Apps, AppObservation{ID: entry.Options.ID, Status: "ready"})
			}
			if len(observation.Apps) == 0 {
				t.Fatal("missing registration fixture")
			}
			observation.Apps[0].ID = id
			if err := c.observe(observation); err == nil {
				t.Fatal("reserved identity accepted")
			}
			for _, instance := range c.Journal.View().Instances {
				if instance.AppID == id {
					t.Fatal("reserved identity persisted")
				}
			}
			instance := &Instance{AppID: id}
			if _, err := AppOptions(instance, true); err == nil {
				t.Fatal("reserved identity advertised ready")
			}
		})
	}
}
