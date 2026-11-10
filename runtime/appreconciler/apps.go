package appreconciler

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/schema"
	runner "github.com/livepeer/golang-runner"
)

func appCount(d schema.DefinitionV1) int { return max(1, len(d.Apps)) }
func appID(i *Instance, n int) string {
	if len(i.Definition.Apps) == 0 {
		return i.AppID
	}
	return fmt.Sprintf("r-%s-%d", i.ID, n)
}
func ownsAppID(i *Instance, id string) bool {
	if len(i.Definition.Apps) == 0 {
		return i.AppID == id
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "r-"+i.ID+"-"))
	return err == nil && n >= 0 && n < len(i.Definition.Apps) && appID(i, n) == id
}
func registrationsAbsent(i *Instance, seen map[string]bool) bool {
	for n := range appCount(i.Definition) {
		if seen[appID(i, n)] {
			return false
		}
	}
	return true
}
func retainedRegistrations(instances map[string]*Instance) int {
	count := 0
	for _, i := range instances {
		if occupied(i) {
			count += appCount(i.Definition)
		}
	}
	return count
}

// One workload allocation, multiple independent Node discovery registrations.
func AppRegistrations(i *Instance, ready bool) ([]Registration, error) {
	if contract.ReservedProxyID(i.AppID) {
		return nil, errors.New("reserved_app_identity")
	}
	d := i.Definition
	apps := d.Apps
	if len(apps) == 0 {
		apps = []schema.App{{Name: d.Name, Capacity: d.Instances.CapacityPerInstance, Price: d.Price}}
	}
	status := "not-ready"
	if ready && i.WithdrawalID == "" {
		status = "ready"
	}
	entries := make([]Registration, len(apps))
	for n, app := range apps {
		price, err := runner.NewPriceInfo(app.Price.Amount, app.Price.Currency, app.Price.Unit)
		if err != nil {
			return nil, err
		}
		options := runner.AppOptions{ID: appID(i, n), App: app.Name, Version: d.AppVersion, RunnerURL: privateURL(i.Name, d.HTTP.Port) + app.Path, Mode: d.Runner.Mode, PriceInfo: price, Capacity: app.Capacity, Status: status, Proxy: true}
		entries[n] = Registration{InstanceID: i.ID, AppIndex: n, Registered: i.AppID != "", WithdrawalID: i.WithdrawalID, WithdrawnAt: i.WithdrawnAt, PodUID: i.PodUID, Options: options}
	}
	return entries, nil
}

// A shared backend is ready for rolling progress only when every alias is ready.
func aggregateObservation(i *Instance, byID map[string]AppObservation) (AppObservation, bool) {
	if len(i.Definition.Apps) == 0 {
		app, ok := byID[i.AppID]
		return app, ok && i.AppID != ""
	}
	result := AppObservation{ID: i.AppID, Status: "ready", SessionIDs: []string{}}
	if i.AppID == "" {
		return result, false
	}
	observed := false
	for n := range appCount(i.Definition) {
		app, ok := byID[appID(i, n)]
		observed = observed || ok
		if !ok || app.Status != "ready" {
			result.Status = "not-ready"
		}
		result.SessionIDs = append(result.SessionIDs, app.SessionIDs...)
	}
	return result, observed
}
