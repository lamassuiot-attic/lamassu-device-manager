package api

import (
	"context"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint              endpoint.Endpoint
	PostDeviceEndpoint          endpoint.Endpoint
	GetDevices                  endpoint.Endpoint
	GetDeviceById               endpoint.Endpoint
	GetDevicesByDMS             endpoint.Endpoint
	DeleteDevice                endpoint.Endpoint
	DeleteRevoke                endpoint.Endpoint
	GetDeviceLogs               endpoint.Endpoint
	GetDeviceCert               endpoint.Endpoint
	GetDeviceCertHistory        endpoint.Endpoint
	GetDmsCertHistoryThirtyDays endpoint.Endpoint
}

func MakeServerEndpoints(s Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var postDeviceEndpoint endpoint.Endpoint
	{
		postDeviceEndpoint = MakePostDeviceEndpoint(s)
		postDeviceEndpoint = opentracing.TraceServer(otTracer, "PostCSR")(postDeviceEndpoint)
	}
	var getDevicesEndpoint endpoint.Endpoint
	{
		getDevicesEndpoint = MakeGetDevicesEndpoint(s)
		getDevicesEndpoint = opentracing.TraceServer(otTracer, "GetDevices")(getDevicesEndpoint)
	}
	var getDevicesByIdEndpoint endpoint.Endpoint
	{
		getDevicesByIdEndpoint = MakeGetDeviceByIdEndpoint(s)
		getDevicesByIdEndpoint = opentracing.TraceServer(otTracer, "GetDeviceById")(getDevicesByIdEndpoint)
	}
	var getDevicesByDMSEndpoint endpoint.Endpoint
	{
		getDevicesByDMSEndpoint = MakeGetDevicesByDMSEndpoint(s)
		getDevicesByDMSEndpoint = opentracing.TraceServer(otTracer, "GetDevicesByDMS")(getDevicesByDMSEndpoint)
	}
	var deleteDeviceEndpoint endpoint.Endpoint
	{
		deleteDeviceEndpoint = MakeDeleteDeviceEndpoint(s)
		deleteDeviceEndpoint = opentracing.TraceServer(otTracer, "DeleteDevice")(deleteDeviceEndpoint)
	}
	var deleteRevokeEndpoint endpoint.Endpoint
	{
		deleteRevokeEndpoint = MakeDeleteRevokeEndpoint(s)
		deleteRevokeEndpoint = opentracing.TraceServer(otTracer, "deleteRevokeEndpoint")(deleteRevokeEndpoint)
	}
	var getDeviceLogsEndpoint endpoint.Endpoint
	{
		getDeviceLogsEndpoint = MakeGetDeviceLogsEndpoint(s)
		getDeviceLogsEndpoint = opentracing.TraceServer(otTracer, "getDeviceLogsEndpoint")(getDeviceLogsEndpoint)
	}
	var getDeviceCertEndpoint endpoint.Endpoint
	{
		getDeviceCertEndpoint = MakeGetDeviceCertEndpoint(s)
		getDeviceCertEndpoint = opentracing.TraceServer(otTracer, "getDeviceCertEndpoint")(getDeviceCertEndpoint)
	}
	var getDeviceCertHistoryEndpoint endpoint.Endpoint
	{
		getDeviceCertHistoryEndpoint = MakeGetDeviceCertHistoryEndpoint(s)
		getDeviceCertHistoryEndpoint = opentracing.TraceServer(otTracer, "getDeviceCertHistoryEndpoint")(getDeviceCertHistoryEndpoint)
	}
	var getDmsCertHistoryThirtyDaysEndpoint endpoint.Endpoint
	{
		getDmsCertHistoryThirtyDaysEndpoint = MakeGetDmsCertHistoryThirtyDaysEndpoint(s)
		getDmsCertHistoryThirtyDaysEndpoint = opentracing.TraceServer(otTracer, "getDmsCertHistoryThirtyDaysEndpoint")(getDmsCertHistoryThirtyDaysEndpoint)
	}

	return Endpoints{
		HealthEndpoint:              healthEndpoint,
		PostDeviceEndpoint:          postDeviceEndpoint,
		GetDevices:                  getDevicesEndpoint,
		GetDeviceById:               getDevicesByIdEndpoint,
		GetDevicesByDMS:             getDevicesByDMSEndpoint,
		DeleteDevice:                deleteDeviceEndpoint,
		DeleteRevoke:                deleteRevokeEndpoint,
		GetDeviceLogs:               getDeviceLogsEndpoint,
		GetDeviceCert:               getDeviceCertEndpoint,
		GetDeviceCertHistory:        getDeviceCertHistoryEndpoint,
		GetDmsCertHistoryThirtyDays: getDmsCertHistoryThirtyDaysEndpoint,
	}
}

func MakeHealthEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return healthResponse{Healthy: healthy}, nil
	}
}

func MakePostDeviceEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(postDeviceRequest)
		device, e := s.PostDevice(ctx, req.Device)
		return postDeviceResponse{Device: device, Err: e}, nil
	}
}

func MakeGetDevicesEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		devices, e := s.GetDevices(ctx)
		return devices.Devices, e
	}
}
func MakeGetDeviceByIdEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getDevicesByIdRequest)
		device, e := s.GetDeviceById(ctx, req.Id)
		return device, e
	}
}
func MakeGetDevicesByDMSEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getDevicesByDMSRequest)
		devices, e := s.GetDevicesByDMS(ctx, req.Id)
		return devices.Devices, e
	}
}
func MakeDeleteDeviceEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(deleteDeviceRequest)
		e := s.DeleteDevice(ctx, req.Id)
		if e != nil {
			return "", e
		} else {
			return "OK", e
		}
	}
}
func MakeDeleteRevokeEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(deleteRevokeRequest)
		e := s.RevokeDeviceCert(ctx, req.Id)
		return nil, e
	}
}
func MakeGetDeviceLogsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getDeviceLogsRequest)
		logs, e := s.GetDeviceLogs(ctx, req.Id)
		return logs.Logs, e
	}
}
func MakeGetDeviceCertEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getDeviceCertRequest)
		deviceCert, e := s.GetDeviceCert(ctx, req.Id)
		return deviceCert, e
	}
}
func MakeGetDeviceCertHistoryEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getDeviceCertHistoryRequest)
		history, e := s.GetDeviceCertHistory(ctx, req.Id)
		return history.DeviceCertHistory, e
	}
}
func MakeGetDmsCertHistoryThirtyDaysEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		history, e := s.GetDmsCertHistoryThirtyDays(ctx)
		return history.DMSCertsHistory, e
	}
}

type healthRequest struct{}

type healthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type postDeviceRequest struct {
	Device device.Device
}

type postDeviceResponse struct {
	Device device.Device `json:"device,omitempty"`
	Err    error         `json:"err,omitempty"`
}

func (r postDeviceResponse) error() error { return r.Err }

type getDevicesResponse struct {
	Devices []device.Device `json:"devices,omitempty"`
	Err     error           `json:"err,omitempty"`
}

type getDevicesByIdRequest struct {
	Id string
}
type getDevicesByDMSRequest struct {
	Id string
}
type deleteDeviceRequest struct {
	Id string
}
type postIssueCertResponse struct {
	Crt string `json:"crt,omitempty"`
	Err error  `json:"err,omitempty"`
}
type postIssueCertUsingDefaultResponse struct {
	Crt     string `json:"crt,omitempty"`
	PrivKey string `json:"priv_key,omitempty"`
	Err     error  `json:"err,omitempty"`
}
type deleteRevokeRequest struct {
	Id string
}
type getDeviceLogsRequest struct {
	Id string
}
type getDeviceCertRequest struct {
	Id string
}
type getDeviceCertHistoryRequest struct {
	Id string
}
