// SPDX-License-Identifier: Apache-2.0
module github.com/example/myapp

go 1.21

toolchain go1.21.5

require (
	github.com/gorilla/mux v1.8.1
	golang.org/x/crypto v0.21.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible
	github.com/old/redirected v1.0.0
	github.com/old/localized v2.0.0+incompatible
	github.com/dropme/excluded v0.9.0
)

replace github.com/old/redirected v1.0.0 => github.com/new/replacement v2.5.0

replace (
	github.com/old/localized => ./vendor/localized
)

exclude (
	github.com/dropme/excluded v0.9.0
)
