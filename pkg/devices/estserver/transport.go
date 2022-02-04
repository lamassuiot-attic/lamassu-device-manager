package estserver

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/configs"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/estserver/mtls"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/utils"
	lamassuest "github.com/lamassuiot/lamassu-est/pkg/server/api"

	"github.com/gorilla/mux"
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
		return context.WithValue(ctx, "LamassuLogger", logger)
	}
}

func MakeHTTPHandler(service lamassuest.Service, verify utils.Utils, logger log.Logger, cfg configs.Config, otTracer stdopentracing.Tracer, ctx context.Context) http.Handler {
	router := mux.NewRouter()
	endpoints := lamassuest.MakeServerEndpoints(service, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(lamassuest.EncodeError),
		httptransport.ServerBefore(mtls.HTTPToContext()),
	}

	// MUST as per rfc7030
	router.Methods("GET").Path("/.well-known/est/cacerts").Handler(httptransport.NewServer(
		endpoints.GetCAsEndpoint,
		lamassuest.DecodeRequest,
		lamassuest.EncodeGetCaCertsResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "cacerts", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/simpleenroll").Handler(httptransport.NewServer(
		mtls.NewParser(true, verify, cfg, ctx)(endpoints.EnrollerEndpoint),
		lamassuest.DecodeEnrollRequest,
		lamassuest.EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simpleenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/simplereenroll").Handler(httptransport.NewServer(
		mtls.NewParser(false, verify, cfg, ctx)(endpoints.ReenrollerEndpoint),
		lamassuest.DecodeReenrollRequest,
		lamassuest.EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simplereenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	router.Methods("POST").Path("/.well-known/est/{aps}/serverkeygen").Handler(httptransport.NewServer(
		mtls.NewParser(true, verify, cfg, ctx)(endpoints.ServerKeyGenEndpoint),
		lamassuest.DecodeServerkeygenRequest,
		lamassuest.EncodeServerkeygenResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "serverkeygen", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return router
}
