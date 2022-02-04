package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"

	"github.com/gorilla/mux"

	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"

	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		logger := log.With(logger, "span_id", stdopentracing.SpanFromContext(ctx))
		return context.WithValue(ctx, "LamassuLogger", logger)
	}
}

func MakeHTTPHandler(s Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := MakeServerEndpoints(s, otTracer)
	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
	}
	r.Methods("GET").Path("/v1/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("POST").Path("/v1/devices").Handler(httptransport.NewServer(
		e.PostDeviceEndpoint,
		decodePostDeviceRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostDevice", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices").Handler(httptransport.NewServer(
		e.GetDevices,
		decodeRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDevices", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}").Handler(httptransport.NewServer(
		e.GetDeviceById,
		decodeGetDeviceById,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceById", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/dms/{dmsId}").Handler(httptransport.NewServer(
		e.GetDevicesByDMS,
		decodeGetDevicesByDMSRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDevicesByDMS", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("DELETE").Path("/v1/devices/{deviceId}").Handler(httptransport.NewServer(
		e.DeleteDevice,
		decodeDeleteDeviceRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteDevice", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("DELETE").Path("/v1/devices/{deviceId}/revoke").Handler(httptransport.NewServer(
		e.DeleteRevoke,
		decodedecodeDeleteRevokeRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteRevoke", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}/logs").Handler(httptransport.NewServer(
		e.GetDeviceLogs,
		decodedecodeGetDeviceLogsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceLogs", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}/cert").Handler(httptransport.NewServer(
		e.GetDeviceCert,
		decodedecodeGetDeviceCertRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}/cert-history").Handler(httptransport.NewServer(
		e.GetDeviceCertHistory,
		decodedecodeGetDeviceCertHistoryRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceCertHistory", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/dms-cert-history/thirty-days").Handler(httptransport.NewServer(
		e.GetDmsCertHistoryThirtyDays,
		decodedecodeGetDmsCertHistoryThirtyDaysRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDmsCertHistoryThirtyDays", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/dms-cert-history/last-issued").Handler(httptransport.NewServer(
		e.GetDmsLastIssueCert,
		decodedecodeGetDmsLastIssueCert,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDmsLastIssueCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}

func decodeRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}

func decodePostDeviceRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var device device.Device
	json.NewDecoder(r.Body).Decode((&device))
	if err != nil {
		return nil, errors.New("cannot decode JSON request")
	}
	req := postDeviceRequest{
		Device: device,
	}
	return req, nil
}

func decodeGetDeviceById(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrInvalidDMSId
	}
	return getDevicesByIdRequest{Id: id}, nil
}

func decodeGetDevicesByDMSRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["dmsId"]
	if !ok {
		return nil, ErrInvalidDMSId
	}
	return getDevicesByDMSRequest{Id: id}, nil
}

func decodeDeleteDeviceRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrInvalidDMSId
	}
	return deleteDeviceRequest{Id: id}, nil
}
func decodedecodeDeleteRevokeRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrInvalidDeviceId
	}
	return deleteRevokeRequest{Id: id}, nil
}
func decodedecodeGetDeviceLogsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrInvalidDeviceId
	}
	return getDeviceLogsRequest{Id: id}, nil
}
func decodedecodeGetDeviceCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrInvalidDeviceId
	}
	return getDeviceCertRequest{Id: id}, nil
}
func decodedecodeGetDeviceCertHistoryRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrInvalidDeviceId
	}
	return getDeviceCertHistoryRequest{Id: id}, nil
}
func decodedecodeGetDmsCertHistoryThirtyDaysRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}
func decodedecodeGetDmsLastIssueCert(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), codeFrom(err))
}

func codeFrom(err error) int {
	switch err {
	case ErrInvalidDeviceRequest, ErrInvalidOperation:
		return http.StatusBadRequest
	case ErrIncorrectType:
		return http.StatusUnsupportedMediaType
	case jwt.ErrTokenExpired, jwt.ErrTokenInvalid, jwt.ErrTokenMalformed, jwt.ErrTokenNotActive, jwt.ErrTokenContextMissing, jwt.ErrUnexpectedSigningMethod:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
