package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device/store"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	_ "github.com/lib/pq"
)

func NewDB(driverName string, dataSourceName string, logger log.Logger) (store.DB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	err = checkDBAlive(db)
	for err != nil {
		level.Warn(logger).Log("msg", "Trying to connect to Device DB")
		err = checkDBAlive(db)
	}

	return &DB{db, logger}, nil
}

type DB struct {
	*sql.DB
	logger log.Logger
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (db *DB) InsertDevice(ctx context.Context, dev device.Device) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	sqlStatement := `
	INSERT INTO device_information(id, alias, status, dms_id,country, state ,locality ,organization ,organization_unit, common_name, key_type, key_bits, key_stregnth, current_cert_serial_number, creation_ts)
	VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	RETURNING id;
	`
	var id string
	span := opentracing.StartSpan("lamassu-device-manager: Insert Device with ID "+id+" in database", opentracing.ChildOf(parentSpan.Context()))
	err := db.QueryRow(sqlStatement,
		dev.Id,
		dev.Alias,
		device.DevicePendingProvision,
		dev.DmsId,
		dev.Country,
		dev.State,
		dev.Locality,
		dev.Organization,
		dev.OrganizationUnit,
		dev.CommonName,
		dev.KeyType,
		dev.KeyBits,
		dev.KeyStrength,
		"",
		time.Now(),
	).Scan(&id)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not insert device with ID "+dev.Id+" in database")
		return err
	}
	level.Info(db.logger).Log("msg", "Device with ID "+id+" inserted in database")
	return nil
}

func (db *DB) SelectAllDevices(ctx context.Context) (device.Devices, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_information
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select All Devices from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Devices from database")
		return device.Devices{}, err
	}
	defer rows.Close()

	devices := make([]device.Device, 0)
	for rows.Next() {
		var dev device.Device
		err := rows.Scan(&dev.Id, &dev.Alias, &dev.Status, &dev.DmsId, &dev.Country, &dev.State, &dev.Locality, &dev.Organization, &dev.OrganizationUnit, &dev.CommonName, &dev.KeyStrength, &dev.KeyType, &dev.KeyBits, &dev.CreationTimestamp, &dev.CurrentCertSerialNumber)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database Device row")
			return device.Devices{}, err
		}
		level.Info(db.logger).Log("msg", "Device with ID "+dev.Id+" read from database")
		devices = append(devices, dev)
	}

	return device.Devices{Devices: devices}, nil
}

func (db *DB) SelectDeviceById(ctx context.Context, id string) (device.Device, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_information where id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select Device by ID "+id+" from database", opentracing.ChildOf(parentSpan.Context()))
	var dev device.Device
	err := db.QueryRow(sqlStatement, id).Scan(
		&dev.Id, &dev.Alias, &dev.Status, &dev.DmsId, &dev.Country, &dev.State, &dev.Locality, &dev.Organization, &dev.OrganizationUnit, &dev.CommonName, &dev.KeyStrength, &dev.KeyType, &dev.KeyBits, &dev.CreationTimestamp, &dev.CurrentCertSerialNumber,
	)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Device "+id+" from database")
		return device.Device{}, err
	}

	return dev, nil
}

func (db *DB) SelectAllDevicesByDmsId(ctx context.Context, dms_id string) (device.Devices, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_information where dms_id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select All Devices by DMS ID from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, dms_id)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Devices from database")
		return device.Devices{}, err
	}
	defer rows.Close()

	var devices []device.Device
	for rows.Next() {
		var dev device.Device
		err := rows.Scan(&dev.Id, &dev.Alias, &dev.Status, &dev.DmsId, &dev.Country, &dev.State, &dev.Locality, &dev.Organization, &dev.OrganizationUnit, &dev.CommonName, &dev.KeyStrength, &dev.KeyType, &dev.KeyBits, &dev.CreationTimestamp, &dev.CurrentCertSerialNumber)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database Device row")
			return device.Devices{}, err
		}
		level.Info(db.logger).Log("msg", "Device with ID "+dev.Id+" read from database")
		devices = append(devices, dev)
	}

	return device.Devices{Devices: devices}, nil
}

func (db *DB) UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE device_information 
	SET status = $2 
	WHERE id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Update Device with ID "+id+" to "+newStatus+" status", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id, newStatus)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not updated Device with ID "+id+" to "+newStatus+" status")
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not updated Device with ID "+id+" to "+newStatus+" status")
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	level.Error(db.logger).Log("err", err, "msg", "Updated device with ID "+id+" to "+newStatus+" status")
	return nil
}

func (db *DB) UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE device_information 
	SET current_cert_serial_number = $2 
	WHERE id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Update Devices Certificate  with ID "+id+" to "+serialNumber+" serial number", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id, serialNumber)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not updated Device with ID "+id+" to "+serialNumber+" serial number")
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not updated Device with ID "+id+" to "+serialNumber+" serial number")
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	level.Error(db.logger).Log("err", err, "msg", "Updated device with ID "+id+" to "+serialNumber+" serial number")
	return nil
}

func (db *DB) DeleteDevice(ctx context.Context, id string) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	DELETE FROM device_information
	WHERE id = $1;
	`
	span := opentracing.StartSpan("lamassu-device-manager: Delete device with ID "+id+" from database", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not delete Device with ID "+id+" from database")
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not delete Device with ID "+id+" from database")
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	return nil
}

func (db *DB) InsertLog(ctx context.Context, logDev device.DeviceLog) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	INSERT INTO device_logs(id, creation_ts, device_uuid, log_type,log_message)
	VALUES($1, $2, $3, $4, $5)
	RETURNING id;
	`
	span := opentracing.StartSpan("lamassu-device-manager:  insert Log Device for device with ID "+logDev.DeviceId+" in database", opentracing.ChildOf(parentSpan.Context()))
	var id = uuid.NewString()
	err := db.QueryRow(sqlStatement,
		id,
		time.Now(),
		logDev.DeviceId,
		logDev.LogType,
		logDev.LogMessage,
	).Scan(&logDev.Id)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not insert Log Device for device with ID "+logDev.DeviceId+" in database")
		return err
	}
	level.Info(db.logger).Log("msg", "Device Log with ID "+id+" inserted in database")
	return nil
}

func (db *DB) SelectDeviceLogs(ctx context.Context, deviceId string) (device.DeviceLogs, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_logs where device_uuid = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select Devoces Logs from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, deviceId)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Devices Logs from database")
		return device.DeviceLogs{}, err
	}
	defer rows.Close()

	var deviceLogs []device.DeviceLog
	for rows.Next() {
		var log device.DeviceLog
		err := rows.Scan(&log.Id, &log.Timestamp, &log.DeviceId, &log.LogType, &log.LogMessage)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database Device row")
			return device.DeviceLogs{}, err
		}
		level.Info(db.logger).Log("msg", "DeviceLog with ID "+log.Id+" read from database")
		deviceLogs = append(deviceLogs, log)
	}

	return device.DeviceLogs{Logs: deviceLogs}, err
}

func (db *DB) InsertDeviceCertHistory(ctx context.Context, certHistory device.DeviceCertHistory) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	// Add TStamp
	sqlStatement := `
	INSERT INTO device_certificates_history(serial_number, device_uuid, issuer_serial_number, issuer_name, status, creation_ts)
	VALUES($1, $2, $3, $4, $5, $6)
	`

	span := opentracing.StartSpan("lamassu-device-manager:insert Devices Cert History for device with SerialNumber "+certHistory.SerialNumber+" in database", opentracing.ChildOf(parentSpan.Context()))
	_, err := db.Exec(sqlStatement,
		certHistory.SerialNumber,
		certHistory.DeviceId,
		certHistory.IssuerSerialNumber,
		certHistory.IsuuerName,
		device.CertHistoryActive,
		time.Now(),
	)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not insert Devices Cert History for device with SerialNumber "+certHistory.SerialNumber+" in database")
		return err
	}
	level.Info(db.logger).Log("msg", "Devices Cert History with Serial Number "+certHistory.SerialNumber+" inserted in database")
	return nil
}

func (db *DB) SelectDeviceCertHistory(ctx context.Context, deviceId string) (device.DeviceCertsHistory, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_certificates_history where device_uuid = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select Devices Cert History from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, deviceId)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Devices Cert History from database")
		return device.DeviceCertsHistory{}, err
	}
	defer rows.Close()

	var deviceCertHistory []device.DeviceCertHistory
	for rows.Next() {
		var certHistory device.DeviceCertHistory
		err := rows.Scan(&certHistory.SerialNumber, &certHistory.DeviceId, &certHistory.IssuerSerialNumber, &certHistory.IsuuerName, &certHistory.Status, &certHistory.CreationTimestamp)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database Device row")
			return device.DeviceCertsHistory{}, err
		}
		level.Info(db.logger).Log("msg", "Devices Cert History with SerialNumber "+certHistory.SerialNumber+" read from database")
		deviceCertHistory = append(deviceCertHistory, certHistory)
	}

	return device.DeviceCertsHistory{DeviceCertHistory: deviceCertHistory}, nil
}

func (db *DB) SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (device.DeviceCertHistory, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_certificates_history where serial_number = $1
	`
	var devCh device.DeviceCertHistory
	span := opentracing.StartSpan("lamassu-device-manager: Select Device Device Cert history with serialNumber: "+serialNumber+" from database", opentracing.ChildOf(parentSpan.Context()))
	err := db.QueryRow(sqlStatement, serialNumber).Scan(
		&devCh.SerialNumber, &devCh.DeviceId, &devCh.IssuerSerialNumber, &devCh.IsuuerName, &devCh.Status, &devCh.CreationTimestamp,
	)
	span.Finish()

	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Device Cert history with serialNumber: "+serialNumber+" from database")
		return device.DeviceCertHistory{}, err
	}

	return devCh, nil
}
func (db *DB) SelectDeviceCertHistoryLastThirtyDays(ctx context.Context) (device.DeviceCertsHistory, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_certificates_history WHERE creation_ts >= NOW() - INTERVAL '30 days'
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select Device Device Cert history Last Thirty Days from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Devices Cert History from database")
		return device.DeviceCertsHistory{}, err
	}
	defer rows.Close()

	var deviceCertHistory []device.DeviceCertHistory
	for rows.Next() {
		var certHistory device.DeviceCertHistory
		err := rows.Scan(&certHistory.SerialNumber, &certHistory.DeviceId, &certHistory.IssuerSerialNumber, &certHistory.IsuuerName, &certHistory.Status, &certHistory.CreationTimestamp)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database Device row")
			return device.DeviceCertsHistory{}, err
		}
		level.Info(db.logger).Log("msg", "Devices Cert History with SerialNumber "+certHistory.SerialNumber+" read from database")
		deviceCertHistory = append(deviceCertHistory, certHistory)
	}

	return device.DeviceCertsHistory{DeviceCertHistory: deviceCertHistory}, nil
}

func (db *DB) UpdateDeviceCertHistory(ctx context.Context, deviceId string, serialNumber string, newStatus string) error {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE device_certificates_history 
	SET status = $2 
	WHERE serial_number = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: updated Devices Cert History with ID "+serialNumber+" to "+newStatus+" status", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, serialNumber, newStatus)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not updated Devices Cert History with ID "+serialNumber+" to "+newStatus+" status")
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not updated Devices Cert History with ID "+serialNumber+" to "+newStatus+" status")
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	level.Error(db.logger).Log("err", err, "msg", "Updated Devices Cert History with ID "+serialNumber+" to "+newStatus+" status")
	return nil
}

func (db *DB) SelectDmssLastIssuedCert(ctx context.Context) (device.DMSsLastIssued, error) {
	db.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM last_issued_cert_by_dms
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select Last Issued Cert By DMS from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Last Issued Cert By DMS from database")
		return device.DMSsLastIssued{}, err
	}
	defer rows.Close()

	var dmssLastIssued []device.DMSLastIssued
	for rows.Next() {
		var lastIssued device.DMSLastIssued
		err := rows.Scan(&lastIssued.DmsId, &lastIssued.Timestamp, &lastIssued.SerialNumber)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database Device row")
			return device.DMSsLastIssued{}, err
		}
		dmssLastIssued = append(dmssLastIssued, lastIssued)
	}

	return device.DMSsLastIssued{DMSLastIssued: dmssLastIssued}, nil
}
