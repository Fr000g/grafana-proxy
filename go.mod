module grafana-proxy

go 1.24.5

replace github.com/onsi/gomega v1.18.1 => github.com/onsi/gomega v1.32.0

require (
	github.com/Luzifer/rconfig v1.2.0
	github.com/google/uuid v1.6.0
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.18.1 // indirect
	github.com/spf13/pflag v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/validator.v2 v2.0.0-20170814132753-460c83432a98 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
