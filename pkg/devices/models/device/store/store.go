package store

import (
	"context"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
)

type DB interface {
	InsertDevice(ctx context.Context, d device.Device) error
	SelectDeviceById(ctx context.Context, id string) (device.Device, error)
	SelectAllDevices(ctx context.Context) (device.Devices, error)
	SelectAllDevicesByDmsId(ctx context.Context, dms_id string) (device.Devices, error)
	UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error
	UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error
	DeleteDevice(ctx context.Context, id string) error

	InsertLog(ctx context.Context, l device.DeviceLog) error
	SelectDeviceLogs(ctx context.Context, id string) (device.DeviceLogs, error)

	InsertDeviceCertHistory(ctx context.Context, l device.DeviceCertHistory) error
	SelectDeviceCertHistory(ctx context.Context, deviceId string) (device.DeviceCertsHistory, error)
	SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (device.DeviceCertHistory, error)
	SelectDeviceCertHistoryLastThirtyDays(ctx context.Context) (device.DeviceCertsHistory, error)
	UpdateDeviceCertHistory(ctx context.Context, deviceId string, serialNumber string, newStatus string) error

	SelectDmssLastIssuedCert(ctx context.Context) (device.DMSsLastIssued, error)
}
