package api

import (
	"context"
	"time"

	deviceModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
)

type Middleware func(Service) Service

func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger log.Logger
}

func (mw loggingMiddleware) Health(ctx context.Context) (healthy bool) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
			"healthy", healthy,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) PostDevice(ctx context.Context, device deviceModel.Device) (deviceResp deviceModel.Device, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PostDevice",
			"id", device.Id,
			"alias", device.Alias,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.PostDevice(ctx, device)
}

func (mw loggingMiddleware) GetDevices(ctx context.Context) (deviceResp devicesModel.Devices, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDevices",
			"deviceResp", deviceResp,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDevices(ctx)
}

func (mw loggingMiddleware) GetDeviceById(ctx context.Context, deviceId string) (deviceResp devicesModel.Device, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceById",
			"deviceId", deviceId,
			"deviceResp", deviceResp,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceById(ctx, deviceId)
}

func (mw loggingMiddleware) GetDevicesByDMS(ctx context.Context, dmsId string) (deviceResp devicesModel.Devices, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDevicesByDMS",
			"dmsId", dmsId,
			"deviceResp", deviceResp,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDevicesByDMS(ctx, dmsId)
}

func (mw loggingMiddleware) DeleteDevice(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteDevice",
			"id", id,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.DeleteDevice(ctx, id)
}

func (mw loggingMiddleware) RevokeDeviceCert(ctx context.Context, id string, revocationReason string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "RevokeDeviceCert",
			"revocationReason", revocationReason,
			"id", id,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.RevokeDeviceCert(ctx, id, revocationReason)
}

func (mw loggingMiddleware) GetDeviceLogs(ctx context.Context, id string) (logs devicesModel.DeviceLogs, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceLogs",
			"id", id,
			"logs", logs,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceLogs(ctx, id)
}

func (mw loggingMiddleware) GetDeviceCert(ctx context.Context, id string) (cert devicesModel.DeviceCert, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceCert",
			"id", id,
			"cert", cert,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceCert(ctx, id)
}

func (mw loggingMiddleware) GetDeviceCertHistory(ctx context.Context, id string) (histo devicesModel.DeviceCertsHistory, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceCertHistory",
			"id", id,
			"histo", histo,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceCertHistory(ctx, id)
}
func (mw loggingMiddleware) GetDmsCertHistoryThirtyDays(ctx context.Context) (certHisto devicesModel.DMSCertsHistory, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDmsCertHistoryThirtyDays",
			"histo", certHisto,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDmsCertHistoryThirtyDays(ctx)
}
func (mw loggingMiddleware) GetDmsLastIssuedCert(ctx context.Context) (dmsLastIssued devicesModel.DMSsLastIssued, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDmsLastIssuedCert",
			"dmsLastIssued", dmsLastIssued,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDmsLastIssuedCert(ctx)
}
