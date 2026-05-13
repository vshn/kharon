module github.com/vshn/kharon

go 1.26.3

require (
	github.com/bored-engineer/go-launchd v0.0.0-20241220214420-b514778f4f80
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/foxcpp/go-mockdns v1.2.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/kevinburke/ssh_config v1.6.0
	github.com/oauth2-proxy/mockoidc v0.0.0-20240214162133-caebfff84d25
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	go.uber.org/multierr v1.11.0
	golang.org/x/crypto v0.51.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.20.0
	k8s.io/client-go v0.36.1
	sigs.k8s.io/yaml v1.6.0
	tailscale.com v1.98.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-jose/go-jose/v3 v3.0.5 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-json-experiment/json v0.0.0-20260505212615-e40f80bf6836 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kisielk/errcheck v1.10.0 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	golang.org/x/exp v0.0.0-20260508232706-74f9aab9d74a // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.36.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260512234627-ef417d054102 // indirect
	k8s.io/utils v0.0.0-20260507154919-ff6756f316d2 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.4.0 // indirect
)

replace github.com/kevinburke/ssh_config => ./hack/ssh_config

tool github.com/kisielk/errcheck
