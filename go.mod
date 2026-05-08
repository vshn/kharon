module github.com/vshn/kharon

go 1.26.2

require (
	github.com/bored-engineer/go-launchd v0.0.0-20241220214420-b514778f4f80
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/foxcpp/go-mockdns v1.2.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/kevinburke/ssh_config v1.6.0
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	go.uber.org/multierr v1.11.0
	golang.org/x/crypto v0.50.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.20.0
	tailscale.com v1.98.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-json-experiment/json v0.0.0-20250813024750-ebf49471dced // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kisielk/errcheck v1.10.0 // indirect
	github.com/miekg/dns v1.1.58 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/kevinburke/ssh_config => ./hack/ssh_config

tool github.com/kisielk/errcheck
