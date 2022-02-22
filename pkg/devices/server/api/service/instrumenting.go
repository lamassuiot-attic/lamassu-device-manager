package service

import (
	"context"
	"fmt"
	"time"

	deviceModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"

	"github.com/go-kit/kit/metrics"
)

type instrumentingMiddleware struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	next           Service
}

func NewInstrumentingMiddleware(counter metrics.Counter, latency metrics.Histogram) Middleware {
	return func(next Service) Service {
		return &instrumentingMiddleware{
			requestCount:   counter,
			requestLatency: latency,
			next:           next,
		}
	}
}

func (mw *instrumentingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", "Health", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.Health(ctx)
}

func (mw *instrumentingMiddleware) PostDevice(ctx context.Context, alias string, deviceID string, DmsID int, KeyMetadata deviceModel.PrivateKeyMetadata, Subject deviceModel.Subject) (deviceResp deviceModel.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "PostDevice", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.PostDevice(ctx, alias, deviceID, DmsID, KeyMetadata, Subject)
}

func (mw *instrumentingMiddleware) GetDevices(ctx context.Context) (device []deviceModel.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDevices", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDevices(ctx)
}

func (mw *instrumentingMiddleware) GetDeviceById(ctx context.Context, deviceId string) (device deviceModel.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceById", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceById(ctx, deviceId)
}

func (mw *instrumentingMiddleware) GetDevicesByDMS(ctx context.Context, dmsId string) (devices []deviceModel.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDevicesByDMS", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDevicesByDMS(ctx, dmsId)
}
func (mw *instrumentingMiddleware) DeleteDevice(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteDevice", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteDevice(ctx, id)
}
func (mw *instrumentingMiddleware) RevokeDeviceCert(ctx context.Context, id string, revocationReason string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "RevokeDeviceCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.RevokeDeviceCert(ctx, id, revocationReason)
}
func (mw *instrumentingMiddleware) GetDeviceLogs(ctx context.Context, id string) (logs []deviceModel.DeviceLog, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceLogs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceLogs(ctx, id)
}
func (mw *instrumentingMiddleware) GetDeviceCert(ctx context.Context, id string) (cert deviceModel.DeviceCert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceCert(ctx, id)
}
func (mw *instrumentingMiddleware) GetDeviceCertHistory(ctx context.Context, id string) (history []deviceModel.DeviceCertHistory, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceCertHistory", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceCertHistory(ctx, id)
}
func (mw *instrumentingMiddleware) GetDmsCertHistoryThirtyDays(ctx context.Context) (history []deviceModel.DMSCertHistory, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDmsCertHistoryThirtyDays", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDmsCertHistoryThirtyDays(ctx)
}
func (mw *instrumentingMiddleware) GetDmsLastIssuedCert(ctx context.Context) (dmsLastIssued []deviceModel.DMSLastIssued, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDmsLastIssuedCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDmsLastIssuedCert(ctx)
}
