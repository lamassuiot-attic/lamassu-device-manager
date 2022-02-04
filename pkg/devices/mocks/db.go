package mocks

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"

	_ "github.com/lib/pq"
)

type MockDB struct {
	*sql.DB
	logger log.Logger
}

func NewDevicedDBMock(t *testing.T) (*MockDB, error) {
	t.Helper()
	db, err := sql.Open("driverName", "dataSourceName")

	if err != nil {
		return nil, err
	}
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	err = checkDBAlive(db)
	for err != nil {
		level.Warn(logger).Log("msg", "Trying to connect to Device DB")
		err = checkDBAlive(db)
	}

	return &MockDB{db, logger}, nil

}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func InsertDevice(ctx context.Context, d device.Device) error {
	return errors.New("d")
}

func SelectDeviceById(ctx context.Context, id string) (device.Device, error) {
	return device.Device{}, errors.New("d")
}
func SelectAllDevices(ctx context.Context) (device.Devices, error) {
	return device.Devices{}, errors.New("d")
}
func SelectAllDevicesByDmsId(ctx context.Context, dms_id string) (device.Devices, error) {
	return device.Devices{}, errors.New("d")
}
func UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error {
	return errors.New("d")
}
func UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error {
	return errors.New("d")
}
func DeleteDevice(ctx context.Context, id string) error {
	return errors.New("d")
}

func InsertLog(ctx context.Context, l device.DeviceLog) error {
	return errors.New("d")
}
func SelectDeviceLogs(ctx context.Context, id string) (device.DeviceLogs, error) {
	return device.DeviceLogs{}, errors.New("d")
}

func InsertDeviceCertHistory(ctx context.Context, l device.DeviceCertHistory) error {
	return errors.New("d")
}
func SelectDeviceCertHistory(ctx context.Context, deviceId string) (device.DeviceCertsHistory, error) {
	return device.DeviceCertsHistory{}, errors.New("d")
}
func SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (device.DeviceCertHistory, error) {
	return device.DeviceCertHistory{}, errors.New("d")
}
func SelectDeviceCertHistoryLastThirtyDays(ctx context.Context) (device.DeviceCertsHistory, error) {
	return device.DeviceCertsHistory{}, errors.New("d")
}
func UpdateDeviceCertHistory(ctx context.Context, deviceId string, serialNumber string, newStatus string) error {
	return errors.New("d")
}

func SelectDmssLastIssuedCert(ctx context.Context) (device.DMSsLastIssued, error) {
	return device.DMSsLastIssued{}, errors.New("d")
}
