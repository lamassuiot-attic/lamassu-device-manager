package service

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	lamassucaclient "github.com/lamassuiot/lamassu-ca/pkg/client"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
	devicesStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device/store"
)

type Service interface {
	Health(ctx context.Context) bool
	PostDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) (devicesModel.Device, error)
	UpdateDeviceById(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) (devicesModel.Device, error)
	GetDevices(ctx context.Context, queryParameters device.QueryParameters) ([]devicesModel.Device, int, error)
	GetDeviceById(ctx context.Context, deviceId string) (devicesModel.Device, error)
	GetDevicesByDMS(ctx context.Context, dmsId string, queryParameters device.QueryParameters) ([]devicesModel.Device, error)
	DeleteDevice(ctx context.Context, id string) error
	RevokeDeviceCert(ctx context.Context, id string, revocationReason string) error

	GetDeviceLogs(ctx context.Context, id string) ([]devicesModel.DeviceLog, error)
	GetDeviceCert(ctx context.Context, id string) (device.DeviceCert, error)
	GetDeviceCertHistory(ctx context.Context, id string) ([]devicesModel.DeviceCertHistory, error)
	GetDmsCertHistoryThirtyDays(ctx context.Context, queryParameters device.QueryParameters) ([]devicesModel.DMSCertHistory, error)
	GetDmsLastIssuedCert(ctx context.Context, queryParameters device.QueryParameters) ([]devicesModel.DMSLastIssued, error)

	//getKeyStrength(keyType string, keyBits int) string
	//_generateCSR(ctx context.Context, keyType string, priv interface{}, commonName string, country string, state string, locality string, org string, orgUnit string) ([]byte, error)
}

type devicesService struct {
	mtx             sync.RWMutex
	devicesDb       devicesStore.DB
	logger          log.Logger
	lamassuCaClient lamassucaclient.LamassuCaClient
}

func NewDevicesService(devicesDb devicesStore.DB, lamassuCa *lamassucaclient.LamassuCaClient, logger log.Logger) Service {

	return &devicesService{
		devicesDb:       devicesDb,
		lamassuCaClient: *lamassuCa,
		logger:          logger,
	}
}

func (s *devicesService) Health(ctx context.Context) bool {
	return true
}

func (s *devicesService) PostDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) (devicesModel.Device, error) {
	err := s.devicesDb.InsertDevice(ctx, alias, deviceID, dmsID, description, tags, iconName, iconColor)
	if err != nil {
		return devicesModel.Device{}, err
	}

	log := devicesModel.DeviceLog{
		DeviceId:   deviceID,
		LogType:    devicesModel.LogDeviceCreated,
		LogMessage: "",
	}
	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return devicesModel.Device{}, err
	}
	log = devicesModel.DeviceLog{
		DeviceId:   deviceID,
		LogType:    devicesModel.LogPendingProvision,
		LogMessage: "",
	}
	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return devicesModel.Device{}, err
	}

	device, err := s.devicesDb.SelectDeviceById(ctx, deviceID)
	if err != nil {
		return devicesModel.Device{}, err
	}
	return device, err
}

func (s *devicesService) UpdateDeviceById(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) (devicesModel.Device, error) {
	err := s.devicesDb.UpdateByID(ctx, alias, deviceID, dmsID, description, tags, iconName, iconColor)
	if err != nil {
		return devicesModel.Device{}, err
	}

	device, err := s.devicesDb.SelectDeviceById(ctx, deviceID)
	if err != nil {
		return devicesModel.Device{}, err
	}
	return device, err
}

func (s *devicesService) GetDevices(ctx context.Context, queryParameters device.QueryParameters) ([]devicesModel.Device, int, error) {
	devices, length, err := s.devicesDb.SelectAllDevices(ctx, queryParameters)
	if err != nil {
		return []devicesModel.Device{}, 0, err
	}
	var dev []devicesModel.Device
	for _, d := range devices {
		if d.CurrentCertificate.SerialNumber != "" {
			currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, d.CurrentCertificate.SerialNumber)
			if err != nil {
				return []devicesModel.Device{}, 0, err
			}

			cert, err := s.lamassuCaClient.GetCert(ctx, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber, "pki")

			if err != nil {
				return []devicesModel.Device{}, 0, err
			}
			d.CurrentCertificate.Valid_to = cert.ValidTo
			d.CurrentCertificate.Cert = cert.CertContent.CerificateBase64
			dev = append(dev, d)
		} else {
			dev = append(dev, d)
		}

	}

	return dev, length, nil
}

func (s *devicesService) GetDevicesByDMS(ctx context.Context, dmsId string, queryParameters device.QueryParameters) ([]devicesModel.Device, error) {
	devices, err := s.devicesDb.SelectAllDevicesByDmsId(ctx, dmsId)
	if err != nil {
		return []devicesModel.Device{}, err
	}

	var dev []devicesModel.Device
	for _, d := range devices {
		if d.CurrentCertificate.SerialNumber != "" {
			currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, d.CurrentCertificate.SerialNumber)
			if err != nil {
				return []devicesModel.Device{}, err
			}

			cert, err := s.lamassuCaClient.GetCert(ctx, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber, "pki")

			if err != nil {
				return []devicesModel.Device{}, err
			}
			d.CurrentCertificate.Valid_to = cert.ValidTo
			d.CurrentCertificate.Cert = cert.CertContent.CerificateBase64
			dev = append(dev, d)
		}
		dev = append(dev, d)

	}

	return dev, nil
}
func (s *devicesService) GetDeviceById(ctx context.Context, deviceId string) (devicesModel.Device, error) {
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		return devicesModel.Device{}, err
	}
	currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, device.CurrentCertificate.SerialNumber)
	if err == nil {
		cert, err := s.lamassuCaClient.GetCert(ctx, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber, "pki")

		if err != nil {
			return devicesModel.Device{}, err
		}
		device.CurrentCertificate.Valid_to = cert.ValidTo
		device.CurrentCertificate.Cert = cert.CertContent.CerificateBase64
	}

	return device, nil
}

func (s *devicesService) DeleteDevice(ctx context.Context, id string) error {
	_ = s.RevokeDeviceCert(ctx, id, "Revocation due to device removal")

	/*
		err := s.devicesDb.DeleteDevice(id)
		if err != nil {
			return err
		}
	*/
	err := s.devicesDb.UpdateDeviceStatusByID(ctx, id, devicesModel.DeviceDecommisioned)
	if err != nil {
		return err
	}

	log := devicesModel.DeviceLog{
		DeviceId:   id,
		LogType:    devicesModel.LogDeviceDecommisioned,
		LogMessage: "",
	}
	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return err
	}
	return err
}

func (s *devicesService) RevokeDeviceCert(ctx context.Context, id string, revocationReason string) error {
	dev, err := s.devicesDb.SelectDeviceById(ctx, id)
	if dev.CurrentCertificate.SerialNumber == "" {
		return err
	}

	if err != nil {
		return err
	}

	currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, dev.CurrentCertificate.SerialNumber)

	if err != nil {
		return err
	}

	serialNumberToRevoke := currentCertHistory.SerialNumber
	// revoke
	err = s.lamassuCaClient.RevokeCert(ctx, currentCertHistory.IsuuerName, serialNumberToRevoke, "pki")
	if err != nil {
		return err
	}

	/*err = s.devicesDb.UpdateDeviceCertHistory(ctx, id, dev.CurrentCertificate.SerialNumber, devicesModel.CertHistoryRevoked)
	if err != nil {
		return err
	}*/

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, id, devicesModel.DeviceCertRevoked)
	if err != nil {
		return err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, id, "")
	if err != nil {
		return err
	}

	log := devicesModel.DeviceLog{
		DeviceId:   id,
		LogType:    devicesModel.LogCertRevoked,
		LogMessage: revocationReason + ". Certificate with Serial Number " + serialNumberToRevoke + " revoked.",
	}
	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return err
	}
	return nil
}

func (s *devicesService) GetDeviceLogs(ctx context.Context, id string) ([]devicesModel.DeviceLog, error) {
	logs, err := s.devicesDb.SelectDeviceLogs(ctx, id)
	if err != nil {
		return []devicesModel.DeviceLog{}, err
	}
	return logs, nil
}

func (s *devicesService) GetDeviceCertHistory(ctx context.Context, id string) ([]devicesModel.DeviceCertHistory, error) {
	history, err := s.devicesDb.SelectDeviceCertHistory(ctx, id)
	var certHistory []devicesModel.DeviceCertHistory
	for _, element := range history {
		dev, err := s.devicesDb.SelectDeviceById(ctx, id)
		if err != nil {
			return []devicesModel.DeviceCertHistory{}, err
		}
		cert, err := s.lamassuCaClient.GetCert(ctx, element.IsuuerName, element.SerialNumber, "pki")
		if err != nil {
			return []devicesModel.DeviceCertHistory{}, err
		}
		t := time.Unix(cert.RevocationTimestamp, 0)
		element.RevocationTimestamp = t.Format("2006-02-01 15:04:05")
		if err != nil {
			return []devicesModel.DeviceCertHistory{}, err
		} else {

			if dev.CreationTimestamp == dev.ModificationTimestamp {
				element.Status = device.DevicePendingProvision
			} else {
				element.Status = cert.Status
			}
		}
		certHistory = append(certHistory, element)

	}
	if err != nil {
		return []devicesModel.DeviceCertHistory{}, err
	}
	return certHistory, nil
}

func (s *devicesService) GetDeviceCert(ctx context.Context, id string) (devicesModel.DeviceCert, error) {
	dev, err := s.devicesDb.SelectDeviceById(ctx, id)
	if dev.CurrentCertificate.SerialNumber == "" {
		return devicesModel.DeviceCert{}, errors.New("The device has no certificate")
	}

	if err != nil {
		return devicesModel.DeviceCert{}, err
	}

	currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, dev.CurrentCertificate.SerialNumber)

	if err != nil {
		return devicesModel.DeviceCert{}, err
	}

	cert, err := s.lamassuCaClient.GetCert(ctx, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber, "pki")

	if err != nil {
		return devicesModel.DeviceCert{}, err
	}

	if dev.CreationTimestamp == dev.ModificationTimestamp {
		currentCertHistory.Status = device.DevicePendingProvision
	} else {
		currentCertHistory.Status = cert.Status
	}

	return devicesModel.DeviceCert{
		DeviceId:     id,
		SerialNumber: cert.SerialNumber,
		Status:       cert.Status,
		CAName:       cert.CAName,
		CRT:          cert.CertContent.CerificateBase64,
		Subject:      devicesModel.Subject(cert.Subject),
		ValidFrom:    cert.ValidFrom,
		ValidTo:      cert.ValidTo,
	}, nil
}

func (s *devicesService) GetDmsCertHistoryThirtyDays(ctx context.Context, queryParameters device.QueryParameters) ([]devicesModel.DMSCertHistory, error) {
	devices, _, err := s.devicesDb.SelectAllDevices(ctx, queryParameters)
	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Could not get devices from DB")
		return []devicesModel.DMSCertHistory{}, err
	}

	deviceDmsMap := make(map[string]string)
	for i := 0; i < len(devices); i++ {
		dev := devices[i]
		deviceDmsMap[dev.Id] = dev.DmsId
	}

	certHistory, err := s.devicesDb.SelectDeviceCertHistoryLastThirtyDays(ctx, queryParameters)

	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Could not get last 30 days issued certs from DB")
		return []devicesModel.DMSCertHistory{}, err
	}

	dmsCertsMap := make(map[string]int) //dmsId -> length

	for i := 0; i < len(certHistory); i++ {
		certHistory := certHistory[i]
		devId := certHistory.DeviceId

		j := dmsCertsMap[deviceDmsMap[devId]]
		if j == 0 {
			// DMS not in map. Add it
			dmsCertsMap[deviceDmsMap[devId]] = 1
		} else {
			dmsCertsMap[deviceDmsMap[devId]] = dmsCertsMap[deviceDmsMap[devId]] + 1
		}
	}

	var dmsCerts []device.DMSCertHistory
	for key, value := range dmsCertsMap {
		dmsCerts = append(dmsCerts, devicesModel.DMSCertHistory{DmsId: key, IssuedCerts: value})
	}

	return dmsCerts, nil
}

func (s *devicesService) GetDmsLastIssuedCert(ctx context.Context, queryParameters device.QueryParameters) ([]devicesModel.DMSLastIssued, error) {
	lastIssued, err := s.devicesDb.SelectDmssLastIssuedCert(ctx, queryParameters)
	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Could not get devices from DB")
		return []devicesModel.DMSLastIssued{}, err
	}
	return lastIssued, nil
}

func _generateCSR(ctx context.Context, keyType string, priv interface{}, commonName string, country string, state string, locality string, org string, orgUnit string) ([]byte, error) {
	var signingAlgorithm x509.SignatureAlgorithm
	if keyType == "EC" {
		signingAlgorithm = x509.ECDSAWithSHA256
	} else {
		signingAlgorithm = x509.SHA256WithRSA

	}
	//emailAddress := csrForm.EmailAddress
	subj := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{state},
		Locality:           []string{locality},
		Organization:       []string{org},
		OrganizationalUnit: []string{orgUnit},
	}
	rawSubj := subj.ToRDNSequence()
	/*rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})*/
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		//EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: signingAlgorithm,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	return csrBytes, err
}
func getKeyStrength(keyType string, keyBits int) string {
	var keyStrength string = "unknown"
	switch keyType {
	case "RSA":
		if keyBits < 2048 {
			keyStrength = "low"
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "EC":
		if keyBits < 224 {
			keyStrength = "low"
		} else if keyBits >= 224 && keyBits < 256 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	}
	return keyStrength
}
