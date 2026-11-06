module github.com/oynozan/bugnet-edges

go 1.27

replace github.com/oynozan/bugnet-proto => ../bugnet-proto

require (
	github.com/pires/go-proxyproto v0.16.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
)

require (
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
