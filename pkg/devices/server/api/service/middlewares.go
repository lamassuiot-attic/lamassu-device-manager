package service

import (
	"context"
	"time"

	deviceModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
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

func (mw loggingMiddleware) PostDevice(ctx context.Context, alias string, deviceID string, DmsID int, KeyMetadata deviceModel.PrivateKeyMetadata, Subject deviceModel.Subject) (deviceResp deviceModel.Device, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PostDevice",
			"id", deviceID,
			"alias", alias,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.PostDevice(ctx, alias, deviceID, DmsID, KeyMetadata, Subject)
}

func (mw loggingMiddleware) GetDevices(ctx context.Context) (deviceResp []deviceModel.Device, err error) {
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

func (mw loggingMiddleware) GetDeviceById(ctx context.Context, deviceId string) (deviceResp deviceModel.Device, err error) {
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

func (mw loggingMiddleware) GetDevicesByDMS(ctx context.Context, dmsId string) (deviceResp []deviceModel.Device, err error) {
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

func (mw loggingMiddleware) GetDeviceLogs(ctx context.Context, id string) (logs []deviceModel.DeviceLog, err error) {
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

func (mw loggingMiddleware) GetDeviceCert(ctx context.Context, id string) (cert deviceModel.DeviceCert, err error) {
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

func (mw loggingMiddleware) GetDeviceCertHistory(ctx context.Context, id string) (histo []deviceModel.DeviceCertHistory, err error) {
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
func (mw loggingMiddleware) GetDmsCertHistoryThirtyDays(ctx context.Context) (certHisto []deviceModel.DMSCertHistory, err error) {
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
func (mw loggingMiddleware) GetDmsLastIssuedCert(ctx context.Context) (dmsLastIssued []deviceModel.DMSLastIssued, err error) {
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
