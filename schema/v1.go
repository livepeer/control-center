// Package schema owns the versioned app contract shared by Control Center and
// Runtime. It performs no I/O, environment expansion, or credential loading.
package schema

const CanonicalFormat = "app-schema-json-v1"
const MaxSourceBytes = 64 << 10
const MaxCanonicalBytes = 512 << 10
const MaxReplicas = 100

// Declaration order is part of CanonicalFormat. Do not reorder fields or change
// v1 defaults/semantics; evolve the versioned contract instead.
type DefinitionV1 struct {
	Name          string     `json:"name" min:"1" max:"128" pattern:"^[A-Za-z0-9][A-Za-z0-9._-]*$"`
	AppVersion    string     `json:"app_version"`
	SchemaVersion int        `json:"schema_version" min:"1" max:"1"`
	Container     Container  `json:"container"`
	Resources     Resources  `json:"resources"`
	HTTP          HTTP       `json:"http"`
	Health        Health     `json:"health"`
	Filesystem    Filesystem `json:"filesystem"`
	Network       Network    `json:"network"`
	Lifecycle     Lifecycle  `json:"lifecycle"`
	Instances     Instances  `json:"instances"`
	Runner        Runner     `json:"runner"`
	Price         Price      `json:"price"`
}
type Container struct {
	Image       string            `json:"image" max:"2048"`
	Platform    *string           `json:"platform" optional:"true" alts:"linux/amd64"`
	Entrypoint  *[]string         `json:"entrypoint" optional:"true" min:"1" max:"64"`
	Command     *[]string         `json:"command" optional:"true" min:"1" max:"64"`
	WorkingDir  *string           `json:"working_dir"`
	User        *string           `json:"user"`
	Environment map[string]string `json:"environment" required:"true" default:"" max:"64"`
}
type Quantities struct {
	CPU              string `json:"cpu" pattern:"^(0|[1-9][0-9]*)m$"`
	Memory           string `json:"memory" pattern:"^(0|[1-9][0-9]*)B$"`
	EphemeralStorage string `json:"ephemeral_storage" pattern:"^(0|[1-9][0-9]*)B$"`
}
type Resources struct {
	Limits   Quantities `json:"limits"`
	Requests Quantities `json:"requests"`
}
type HTTP struct {
	Port int `json:"port" min:"1" max:"65535"`
}
type Health struct {
	Readiness Readiness `json:"readiness"`
}
type Readiness struct {
	Type             string  `json:"type" default:"tcp" alts:"http,tcp"`
	Path             *string `json:"path"`
	Interval         string  `json:"interval" default:"5s" pattern:"^(0|[1-9][0-9]*)s$"`
	Timeout          string  `json:"timeout" default:"2s" pattern:"^(0|[1-9][0-9]*)s$"`
	FailureThreshold int     `json:"failure_threshold" default:"3" min:"1" max:"10"`
}
type Filesystem struct {
	ReadOnlyRoot bool      `json:"read_only_root" default:"true" alts:"true"`
	ShmSize      string    `json:"shm_size" default:"67108864B" pattern:"^(0|[1-9][0-9]*)B$"`
	Scratch      []Scratch `json:"scratch" required:"true" default:"[]" max:"16"`
}
type Scratch struct {
	Path string `json:"path"`
	Size string `json:"size" pattern:"^(0|[1-9][0-9]*)B$"`
}
type Network struct {
	Egress string `json:"egress" default:"deny" alts:"deny"`
}
type Lifecycle struct {
	StartupTimeout  string  `json:"startup_timeout" default:"120s" pattern:"^(0|[1-9][0-9]*)s$"`
	StopSignal      *string `json:"stop_signal" optional:"true" alts:"SIGHUP,SIGINT,SIGQUIT,SIGILL,SIGTRAP,SIGABRT,SIGBUS,SIGFPE,SIGUSR1,SIGSEGV,SIGUSR2,SIGPIPE,SIGALRM,SIGTERM,SIGSTKFLT,SIGCHLD,SIGCONT,SIGTSTP,SIGTTIN,SIGTTOU,SIGURG,SIGXCPU,SIGXFSZ,SIGVTALRM,SIGPROF,SIGWINCH,SIGIO,SIGPWR,SIGSYS"`
	StopGracePeriod string  `json:"stop_grace_period" default:"30s" pattern:"^(0|[1-9][0-9]*)s$"`
}
type Instances struct {
	Mode                string `json:"mode" default:"reusable" alts:"reusable,single-session"`
	Replicas            int    `json:"replicas" default:"1" min:"1" max:"100"`
	CapacityPerInstance int    `json:"capacity_per_instance" default:"1" min:"1" max:"10000"`
}
type Runner struct {
	Mode string `json:"mode" default:"persistent" alts:"persistent,single-shot"`
}
type Price struct {
	Amount   string `json:"amount" default:"0" max:"128" pattern:"^(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?$"`
	Currency string `json:"currency" default:"usd" alts:"usd"`
	Unit     string `json:"unit" default:"hour" alts:"hour,fixed"`
}

type PaymentMode string

const (
	Offchain PaymentMode = "offchain"
	Onchain  PaymentMode = "onchain"
)

type FieldError struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ValidationError struct {
	Fields []FieldError `json:"fields"`
}

func (e *ValidationError) Error() string { return "invalid app definition" }
func (e *ValidationError) add(path, message string) {
	if len(e.Fields) < 32 {
		e.Fields = append(e.Fields, FieldError{path, "invalid_field", message})
	}
}
func (e *ValidationError) err() error {
	if len(e.Fields) > 0 {
		return e
	}
	return nil
}
