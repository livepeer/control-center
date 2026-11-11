package appreconciler

import (
	"testing"
	"time"
)

func TestReservedHostnamesCannotBecomeAcceptedAppIdentities(t *testing.T) {
	for _, id := range []string{"api", "discovery", "api-aaaaaaa", "discovery-aaaaaaa", "app-valid"} {
		t.Run(id, func(t *testing.T) {
			c, _, cluster, owner, _, _ := fixtureController(t)
			registerApps(t, c, cluster)
			request := copyRequest(owner.accepted)
			// Treat one entry as a first registration, so rejection cannot come
			// merely from changing an already-bound app identity.
			if err := c.Journal.Update(func(s *State) error { s.Instances[request.Entries[0].InstanceID].AppID = ""; return nil }); err != nil {
				t.Fatal(err)
			}
			before := c.Journal.View()
			sequence := uint64(0)
			if before.Identity.Sequence != nil {
				sequence = *before.Identity.Sequence + 1
			}
			observation := Observation{Epoch: request.Epoch, RunnerID: request.Identity.RunnerID, Credential: before.Identity.Credential, PreviousCredential: before.Identity.Credential, Accepted: true, Sequence: sequence, At: c.now(), TTL: 30 * time.Second, Entries: request.Entries}
			for _, entry := range request.Entries {
				observation.Apps = append(observation.Apps, AppObservation{ID: entry.Options.ID, Status: "ready", SessionIDs: []string{}})
			}
			if len(observation.Apps) == 0 {
				t.Fatal("missing registration fixture")
			}
			observation.Apps[0].ID = id
			observation.Entries[0].Options.ID = id
			err := c.observe(observation)
			instance := &Instance{AppID: id, Definition: before.Instances[request.Entries[0].InstanceID].Definition}
			_, optionsErr := AppOptions(instance)
			if id == "app-valid" {
				if err != nil || optionsErr != nil {
					t.Fatal("valid identity rejected", err, optionsErr)
				}
				return
			}
			if err == nil || err.Error() != "app_identity" {
				t.Fatal("reserved identity did not reach identity validation", err)
			}
			for _, instance := range c.Journal.View().Instances {
				if instance.AppID == id {
					t.Fatal("reserved identity persisted")
				}
			}
			if optionsErr == nil {
				t.Fatal("reserved identity advertised ready")
			}
		})
	}
}
