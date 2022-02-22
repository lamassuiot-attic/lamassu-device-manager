package store

import (
	"context"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
)

type DB interface {
	InsertDevice(ctx context.Context, alias string, deviceID string, dmsID int, privateKeyMetadata device.PrivateKeyMetadataWithStregth, subject device.Subject) error
	SelectDeviceById(ctx context.Context, id string) (device.Device, error)
	SelectAllDevices(ctx context.Context) ([]device.Device, error)
	SelectAllDevicesByDmsId(ctx context.Context, dms_id string) ([]device.Device, error)
	UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error
	UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error
	DeleteDevice(ctx context.Context, id string) error

	InsertLog(ctx context.Context, l device.DeviceLog) error
	SelectDeviceLogs(ctx context.Context, id string) ([]device.DeviceLog, error)

	InsertDeviceCertHistory(ctx context.Context, l device.DeviceCertHistory) error
	SelectDeviceCertHistory(ctx context.Context, deviceId string) ([]device.DeviceCertHistory, error)
	SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (device.DeviceCertHistory, error)
	SelectDeviceCertHistoryLastThirtyDays(ctx context.Context) ([]device.DeviceCertHistory, error)
	UpdateDeviceCertHistory(ctx context.Context, deviceId string, serialNumber string, newStatus string) error

	SelectDmssLastIssuedCert(ctx context.Context) ([]device.DMSLastIssued, error)
}
