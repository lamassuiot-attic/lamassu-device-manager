package dmsdb

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/dms/store"
	"github.com/lamassuiot/lamassu-dms-enroller/pkg/server/models/dms"
	"github.com/opentracing/opentracing-go"
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
func (db *DB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT *
	FROM public.dms_store
	WHERE serialNumber = $1;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain DMS with SerialNumber "+SerialNumber+" from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, SerialNumber)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain DMS")
		return "", err
	}
	span.Finish()
	defer rows.Close()
	var d dms.DMS
	for rows.Next() {

		err = rows.Scan(&d.Id, &d.Name, &d.SerialNumber, &d.KeyMetadata.KeyType, &d.KeyMetadata.KeyBits, &d.CsrBase64, &d.Status, &d.CreationTimestamp, &d.ModificationTimestamp)
		if err != nil {
			return "", err
		}
	}
	return d.Id, nil
}
func (db *DB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * 
	FROM authorized_cas
	WHERE dmsid = $1;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain Authorized CAs with DMS ID"+dmsid+"from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, dmsid)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain DMSs from database or the database is empty")
		return nil, err
	}
	defer rows.Close()
	cass := make([]dms.AuthorizedCAs, 0)

	for rows.Next() {
		var d dms.AuthorizedCAs
		err := rows.Scan(&d.DmsId, &d.CaName)
		if err != nil {
			return nil, err
		}
		cass = append(cass, d)
	}
	if err = rows.Err(); err != nil {
		level.Debug(db.logger).Log("err", err)
		return nil, err
	}
	level.Debug(db.logger).Log("msg", strconv.Itoa(len(cass))+" DMSs read from database")
	return cass, nil
}
