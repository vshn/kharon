module github.com/bastjan/smart-access

go 1.26.1

require (
	github.com/kevinburke/ssh_config v1.6.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.49.0
	golang.org/x/sync v0.20.0
	tailscale.com v1.96.5
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-json-experiment/json v0.0.0-20250813024750-ebf49471dced // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/sys v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/kevinburke/ssh_config => ./hack/ssh_config
