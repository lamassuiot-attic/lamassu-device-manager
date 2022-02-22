package estserver

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/configs"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/estserver/mtls"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/utils"
	estEndpoint "github.com/lamassuiot/lamassu-est/pkg/server/api/endpoint"
	estService "github.com/lamassuiot/lamassu-est/pkg/server/api/service"
	esttransport "github.com/lamassuiot/lamassu-est/pkg/server/api/transport"
	stdopentracing "github.com/opentracing/opentracing-go"
)

func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		uberTraceId := req.Header.Values("Uber-Trace-Id")
		if uberTraceId != nil {
			logger = log.With(logger, "span_id", uberTraceId)
		} else {
			span := stdopentracing.SpanFromContext(ctx)
			logger = log.With(logger, "span_id", span)
		}
		return context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)
	}
}

func MakeHTTPHandler(service estService.Service, verify utils.Utils, logger log.Logger, cfg configs.Config, otTracer stdopentracing.Tracer, ctx context.Context) http.Handler {
	router := mux.NewRouter()
	endpoints := estEndpoint.MakeServerEndpoints(service, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(esttransport.EncodeError),
		httptransport.ServerBefore(mtls.HTTPToContext()),
	}

	// MUST as per rfc7030
	router.Methods("GET").Path("/.well-known/est/cacerts").Handler(httptransport.NewServer(
		endpoints.GetCAsEndpoint,
		esttransport.DecodeRequest,
		esttransport.EncodeGetCaCertsResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "cacerts", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/simpleenroll").Handler(httptransport.NewServer(
		mtls.NewParser(true, verify, cfg, ctx)(endpoints.EnrollerEndpoint),
		esttransport.DecodeEnrollRequest,
		esttransport.EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simpleenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/simplereenroll").Handler(httptransport.NewServer(
		mtls.NewParser(false, verify, cfg, ctx)(endpoints.ReenrollerEndpoint),
		esttransport.DecodeReenrollRequest,
		esttransport.EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simplereenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	router.Methods("POST").Path("/.well-known/est/{aps}/serverkeygen").Handler(httptransport.NewServer(
		//mtls.NewParser(true, verify, cfg, ctx)(endpoints.ServerKeyGenEndpoint),
		endpoints.ServerKeyGenEndpoint,
		esttransport.DecodeServerkeygenRequest,
		esttransport.EncodeServerkeygenResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "serverkeygen", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return router
}
