package store

import (
	"context"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
)

type DB interface {
	InsertDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error
	SelectDeviceById(ctx context.Context, id string) (device.Device, error)
	SelectAllDevices(ctx context.Context, queryParameters device.QueryParameters) ([]device.Device, int, error)
	SelectAllDevicesByDmsId(ctx context.Context, dms_id string) ([]device.Device, error)
	UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error

	UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error
	DeleteDevice(ctx context.Context, id string) error
	UpdateByID(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error
	InsertLog(ctx context.Context, l device.DeviceLog) error
	SelectDeviceLogs(ctx context.Context, id string) ([]device.DeviceLog, error)

	InsertDeviceCertHistory(ctx context.Context, l device.DeviceCertHistory) error
	SelectDeviceCertHistory(ctx context.Context, deviceId string) ([]device.DeviceCertHistory, error)
	//CalculateDeviceStatus(ctx context.Context, serialNumber string, issuerName string, deviceId string, lamassuCaClient lamassuca.LamassuCaClient) (string, error)
	SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (device.DeviceCertHistory, error)
	SelectDeviceCertHistoryLastThirtyDays(ctx context.Context, queryParameters device.QueryParameters) ([]device.DeviceCertHistory, error)
	//UpdateDeviceCertHistory(ctx context.Context, deviceId string, serialNumber string, newStatus string) error

	SelectDmssLastIssuedCert(ctx context.Context, queryParameters device.QueryParameters) ([]device.DMSLastIssued, error)
}
