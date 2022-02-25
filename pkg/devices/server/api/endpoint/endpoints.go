package endpoint

import (
	"context"
	"math"

	"github.com/go-playground/validator/v10"
	devmanagererrors "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/api/errors"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/api/service"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"

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
	GetDmsLastIssueCert         endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
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
	var getDmsLastIssueCertEndpoint endpoint.Endpoint
	{
		getDmsLastIssueCertEndpoint = MakeGetDmsLastIssueCertEndpoint(s)
		getDmsLastIssueCertEndpoint = opentracing.TraceServer(otTracer, "getDmsLastIssueCertEndpoint")(getDmsLastIssueCertEndpoint)
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
		GetDmsLastIssueCert:         getDmsLastIssueCertEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakePostDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CreateDeviceRequest)
		err = ValidateCreatrCARequest(req)
		if err != nil {
			valError := devmanagererrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		device, e := s.PostDevice(ctx, req.Alias, req.DeviceID, req.DmsId, device.PrivateKeyMetadata(req.KeyMetadata), device.Subject(req.Subject))
		return device, e
	}
}

func MakeGetDevicesEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		devices, e := s.GetDevices(ctx)
		return devices, e
	}
}
func MakeGetDeviceByIdEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDevicesByIdRequest)
		device, e := s.GetDeviceById(ctx, req.Id)
		return device, e
	}
}
func MakeGetDevicesByDMSEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDevicesByDMSRequest)
		devices, e := s.GetDevicesByDMS(ctx, req.Id)
		return devices, e
	}
}
func MakeDeleteDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteDeviceRequest)
		e := s.DeleteDevice(ctx, req.Id)
		if e != nil {
			return "", e
		} else {
			return "OK", e
		}
	}
}
func MakeDeleteRevokeEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteRevokeRequest)
		e := s.RevokeDeviceCert(ctx, req.Id, "Manual revocation")
		return nil, e
	}
}
func MakeGetDeviceLogsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDeviceLogsRequest)
		logs, e := s.GetDeviceLogs(ctx, req.Id)
		return logs, e
	}
}
func MakeGetDeviceCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDeviceCertRequest)
		deviceCert, e := s.GetDeviceCert(ctx, req.Id)
		return deviceCert, e
	}
}
func MakeGetDeviceCertHistoryEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDeviceCertHistoryRequest)
		history, e := s.GetDeviceCertHistory(ctx, req.Id)
		return history, e
	}
}
func MakeGetDmsCertHistoryThirtyDaysEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		history, e := s.GetDmsCertHistoryThirtyDays(ctx)
		return history, e
	}
}
func MakeGetDmsLastIssueCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		history, e := s.GetDmsLastIssuedCert(ctx)
		return history, e
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type CreateDeviceRequest struct {
	DeviceID string `json:"id" validate:"required"`
	Alias    string `json:"alias" validate:"required"`
	DmsId    int    `json:"dms_id" validate:"required"`
	Subject  struct {
		CN string `json:"common_name" validate:"required"`
		O  string `json:"organization"`
		OU string `json:"organization_unit"`
		C  string `json:"country"`
		ST string `json:"state"`
		L  string `json:"locality"`
	} `json:"subject"`
	KeyMetadata struct {
		KeyType string `json:"type" validate:"oneof='rsa' 'ec'"`
		KeyBits int    `json:"bits" validate:"required"`
	} `json:"key_metadata" validate:"required"`
}

func ValidateCreatrCARequest(request CreateDeviceRequest) error {
	CreateCARequestStructLevelValidation := func(sl validator.StructLevel) {
		req := sl.Current().Interface().(CreateDeviceRequest)
		switch req.KeyMetadata.KeyType {
		case "rsa":
			if math.Mod(float64(req.KeyMetadata.KeyBits), 1024) != 0 || req.KeyMetadata.KeyBits < 2048 {
				sl.ReportError(req.KeyMetadata.KeyBits, "bits", "Bits", "bits1024multipleAndGt2048", "")
			}
		case "ec":
			if req.KeyMetadata.KeyBits != 224 || req.KeyMetadata.KeyBits != 256 || req.KeyMetadata.KeyBits != 384 {
				sl.ReportError(req.KeyMetadata.KeyBits, "bits", "Bits", "bitsEcdsaMultiple", "")
			}
		}
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateCARequestStructLevelValidation, CreateDeviceRequest{})
	return validate.Struct(request)
}

type PostDeviceResponse struct {
	Device device.Device `json:"device,omitempty"`
	Err    error         `json:"err,omitempty"`
}

func (r PostDeviceResponse) error() error { return r.Err }

type GetDevicesResponse struct {
	Devices []device.Device `json:"devices,omitempty"`
	Err     error           `json:"err,omitempty"`
}

type GetDevicesByIdRequest struct {
	Id string
}
type GetDevicesByDMSRequest struct {
	Id string
}
type DeleteDeviceRequest struct {
	Id string
}
type PostIssueCertResponse struct {
	Crt string `json:"crt,omitempty"`
	Err error  `json:"err,omitempty"`
}
type PostIssueCertUsingDefaultResponse struct {
	Crt     string `json:"crt,omitempty"`
	PrivKey string `json:"priv_key,omitempty"`
	Err     error  `json:"err,omitempty"`
}
type DeleteRevokeRequest struct {
	Id string
}
type GetDeviceLogsRequest struct {
	Id string
}
type GetDeviceCertRequest struct {
	Id string
}
type GetDeviceCertHistoryRequest struct {
	Id string
}
