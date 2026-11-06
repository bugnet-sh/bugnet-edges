module github.com/oynozan/bugnet-edges

go 1.27

replace github.com/oynozan/bugnet-proto => ../bugnet-proto

require (
	connectrpc.com/connect v1.21.1
	github.com/oynozan/bugnet-proto v0.1.0
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/pires/go-proxyproto v0.16.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	golang.org/x/time v0.14.0
	google.golang.org/protobuf v1.36.12
)

require golang.org/x/text v0.43.0 // indirect
