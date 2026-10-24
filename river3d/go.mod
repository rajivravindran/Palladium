module github.com/rajiv/river3/river3d

go 1.24.7

replace golang.org/x/sys => github.com/golang/sys v0.30.0

require github.com/cilium/ebpf v0.17.3

require golang.org/x/sys v0.30.0

require river3.local/policy v0.0.0

replace river3.local/policy => ../policy
