module github.com/lamassuiot/lamassu-device-manager

go 1.16

// replace github.com/lamassuiot/lamassu-ca => /home/ikerlan/lamassu/lamassu-ca/

// replace github.com/lamassuiot/lamassu-est => /home/ikerlan/lamassu/lamassu-est/

require (
	github.com/armon/go-metrics v0.3.10 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fatih/color v1.13.0 // indirect
	github.com/getkin/kin-openapi v0.88.0
	github.com/go-kit/kit v0.12.0
	github.com/go-kit/log v0.2.0
	github.com/go-openapi/runtime v0.21.1
	github.com/go-playground/validator/v10 v10.10.0
	github.com/google/btree v1.0.1 // indirect
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/consul/api v1.12.0
	github.com/hashicorp/go-hclog v1.0.0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lamassuiot/lamassu-ca v1.0.13
	github.com/lamassuiot/lamassu-est v0.2.4
	github.com/lib/pq v1.10.3
	github.com/mattn/go-colorable v0.1.11 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/opentracing/opentracing-go v1.2.0
	github.com/prometheus/client_golang v1.11.0
	github.com/uber/jaeger-client-go v2.30.0+incompatible
	google.golang.org/grpc v1.41.0 // indirect
)
