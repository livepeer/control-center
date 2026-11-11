package appreconciler

import (
	"errors"
	"math"
	"math/big"
	"strings"

	"github.com/livepeer/control-center/schema"
)

// Resources are integer millicores and bytes. Budgets include retained incarnations.
type Resources struct{ CPU, Memory, Storage int64 }

func quantity(value string, cpu bool) (int64, error) {
	suffixes := []struct {
		suffix                 string
		numerator, denominator int64
	}{
		{"Ki", 1 << 10, 1}, {"Mi", 1 << 20, 1}, {"Gi", 1 << 30, 1}, {"Ti", 1 << 40, 1},
		{"Pi", 1 << 50, 1}, {"Ei", 1 << 60, 1}, {"K", 1000, 1}, {"M", 1000000, 1}, {"G", 1000000000, 1},
		{"T", 1000000000000, 1}, {"m", 1, 1000}, {"u", 1, 1000000}, {"n", 1, 1000000000},
	}
	n, d := int64(1), int64(1)
	for _, s := range suffixes {
		if strings.HasSuffix(value, s.suffix) {
			value = strings.TrimSuffix(value, s.suffix)
			n, d = s.numerator, s.denominator
			break
		}
	}
	r, ok := new(big.Rat).SetString(value)
	if !ok || r.Sign() < 0 {
		return 0, errors.New("resource_quantity")
	}
	r.Mul(r, new(big.Rat).SetFrac64(n, d))
	if cpu {
		r.Mul(r, big.NewRat(1000, 1))
	}
	result := new(big.Int).Quo(r.Num(), r.Denom())
	if !result.IsInt64() {
		return 0, errors.New("resource_quantity")
	}
	return result.Int64(), nil
}
func resources(q schema.Quantities) Resources {
	cpu, _ := quantity(q.CPU, true)
	mem, _ := quantity(strings.TrimSuffix(q.Memory, "B"), false)
	storage, _ := quantity(strings.TrimSuffix(q.EphemeralStorage, "B"), false)
	return Resources{cpu, mem, storage}
}
func fits(instances map[string]*Instance, definition schema.DefinitionV1, budget Resources) bool {
	wanted := resources(definition.Resources.Limits)
	for _, i := range instances {
		if i.Phase == "removed" && i.RegistrationGone {
			continue
		}
		cost := resources(i.Definition.Resources.Limits)
		if wanted.CPU > math.MaxInt64-cost.CPU || wanted.Memory > math.MaxInt64-cost.Memory || wanted.Storage > math.MaxInt64-cost.Storage {
			return false
		}
		wanted.CPU += cost.CPU
		wanted.Memory += cost.Memory
		wanted.Storage += cost.Storage
	}
	return wanted.CPU <= budget.CPU && wanted.Memory <= budget.Memory && wanted.Storage <= budget.Storage
}
