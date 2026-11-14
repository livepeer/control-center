package appreconciler

import "time"

const archiveBudget = 512 << 20

func (c *Controller) collect(view View, now time.Time) error {
	pinned := map[string]bool{view.Artifact: true, view.Applied: true}
	err := c.Journal.Update(func(s *State) error {
		for _, digest := range []string{s.Staged, s.Published, s.Applied} {
			pinned[digest] = true
		}
		if s.Report != nil {
			for _, digest := range []string{s.Report.Apps.StagedDigest, s.Report.Apps.PublishedDigest, s.Report.Apps.AppliedDigest} {
				pinned[digest] = true
			}
		}
		for _, r := range s.Receipts {
			if !r.Done {
				pinned[r.ArtifactDigest] = true
			}
		}
		for digest := range s.Snapshots {
			if !pinned[digest] {
				delete(s.Snapshots, digest)
			}
		}
		wanted := map[string]bool{}
		for _, g := range s.Payload.Index.Groups {
			wanted[g.Key] = true
		}
		for id, i := range s.Instances {
			if i.Phase != "removed" || !i.RegistrationGone || i.SecretPrepared || (c.Secrets != nil && !i.SecretCleanupDone) {
				continue
			}
			if wanted[i.Group.Key] && s.Heads[i.Group.Key] == id {
				continue
			}
			pending := false
			for _, r := range s.Receipts {
				if !r.Done && r.RevisionID == i.Group.RevisionID && r.ActivationGeneration == i.Group.ActivationGeneration {
					pending = true
				}
			}
			if pending {
				continue
			}
			delete(s.Instances, id)
			if s.Heads[i.Group.Key] == id {
				delete(s.Heads, i.Group.Key)
			}
		}
		for revision := range s.SecretRollouts {
			if !secretRevisionRelevant(*s, revision) {
				delete(s.SecretRollouts, revision)
				delete(s.SecretRotationSlots, revision)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return c.Store.Collect(pinned, archiveBudget-2*(16<<20), now)
}
