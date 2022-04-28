package estserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/go-kit/kit/log"

	"github.com/go-kit/log/level"
	lamassuca "github.com/lamassuiot/lamassu-ca/pkg/client"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
	devicesStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device/store"
	dmsStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/dms/store"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/utils"
	esterror "github.com/lamassuiot/lamassu-est/pkg/server/api/errors"
	lamassuest "github.com/lamassuiot/lamassu-est/pkg/server/api/service"
)

type EstService struct {
	logger          log.Logger
	lamassuCaClient lamassuca.LamassuCaClient
	verifyUtils     utils.Utils
	devicesDb       devicesStore.DB
	dmsDb           dmsStore.DB
	minReenrollDays int
}

func NewEstService(lamassuCaClient *lamassuca.LamassuCaClient, verifyUtils *utils.Utils, devicesDb devicesStore.DB, dmsDb dmsStore.DB, minReenrollDays int, logger log.Logger) lamassuest.Service {

	return &EstService{
		lamassuCaClient: *lamassuCaClient,
		logger:          logger,
		verifyUtils:     *verifyUtils,
		devicesDb:       devicesDb,
		dmsDb:           dmsDb,
		minReenrollDays: minReenrollDays,
	}
}

type EstServiceI interface {
	Health(ctx context.Context) bool
	CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error)
	Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate, r *http.Request) (*x509.Certificate, error)
	Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error)
	ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error)
}

func (s *EstService) Health(ctx context.Context) bool {
	return true
}

func (s *EstService) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {

	certs, err := s.lamassuCaClient.GetCAs(ctx, "pki")
	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Error in client request")
		valError := esterror.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}

	x509Certificates := []*x509.Certificate{}
	for _, v := range certs.Certs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		cert, _ := x509.ParseCertificate(block.Bytes)
		x509Certificates = append(x509Certificates, cert)
	}
	level.Debug(s.logger).Log("msg", "Certificates sent CACerts method")
	return x509Certificates, nil
}

func (s *EstService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate, r *http.Request) (*x509.Certificate, error) {
	var PrivateKeyMetadataWithStregth devicesModel.PrivateKeyMetadataWithStregth
	var dmsDB dmsStore.DB
	deviceId := csr.Subject.CommonName
	sn := s.verifyUtils.InsertNth(s.verifyUtils.ToHexInt(cert.SerialNumber), 2)
	dmsId, err := s.dmsDb.SelectBySerialNumber(ctx, sn)
	if err != nil {
		return nil, err
	}
	aps, err = s.verifyCaName(ctx, aps, dmsDB, dmsId)
	if aps == "" {
		level.Debug(s.logger).Log("err", err, "msg", "Error CA Name")
		authError := esterror.UnAuthorized{
			ResourceType: "CA Name",
			ResourceId:   dmsId,
		}
		return &x509.Certificate{}, &authError
	}
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		err = s.devicesDb.InsertDevice(ctx, csr.Subject.CommonName, csr.Subject.CommonName, dmsId, "", []string{}, "Cg/CgSmartphoneChip", "#0068D1")
		if err != nil {
			return nil, err
		}

	}
	device, _ = s.devicesDb.SelectDeviceById(ctx, deviceId)
	if device.Status == devicesModel.DeviceDecommisioned {
		return nil, errors.New("cant issue a certificate for a decommisioned device")
	}

	if device.Status == devicesModel.DeviceProvisioned {
		return nil, errors.New("The device (" + deviceId + ") already has a valid certificate")
	}

	dataCert, err := s.lamassuCaClient.SignCertificateRequest(ctx, aps, csr, "pki", true)
	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Error in client request")
		valError := esterror.ValidationError{
			Msg: err.Error(),
		}
		return &x509.Certificate{}, &valError
	}
	deviceId = dataCert.Subject.CommonName
	level.Debug(s.logger).Log("msg", csr.PublicKeyAlgorithm.String())
	switch csr.PublicKeyAlgorithm.String() {
	case "RSA":
		PrivateKeyMetadataWithStregth.KeyType = "RSA"
		rsaPublicKey := csr.PublicKey.(*rsa.PublicKey)
		PrivateKeyMetadataWithStregth.KeyBits = rsaPublicKey.Size() * 8
	case "ECDSA":
		PrivateKeyMetadataWithStregth.KeyType = "EC"
		ecPublicKey := csr.PublicKey.(*ecdsa.PublicKey)
		PrivateKeyMetadataWithStregth.KeyBits = ecPublicKey.Curve.Params().BitSize
	}
	PrivateKeyMetadataWithStregth.KeyStrength = getKeyStrength(PrivateKeyMetadataWithStregth.KeyType, PrivateKeyMetadataWithStregth.KeyBits)
	level.Debug(s.logger).Log("msg", PrivateKeyMetadataWithStregth)
	subject := devicesModel.Subject{
		CN: csr.Subject.CommonName,
		O:  csr.Subject.Organization[0],
		OU: csr.Subject.OrganizationalUnit[0],
		C:  csr.Subject.Country[0],
		ST: csr.Subject.Province[0],
		L:  csr.Subject.Locality[0],
	}
	err = s.devicesDb.SetKeyAndSubject(ctx, PrivateKeyMetadataWithStregth, subject, subject.CN)
	if err != nil {
		return nil, err
	}
	serialNumber := s.verifyUtils.InsertNth(s.verifyUtils.ToHexInt(dataCert.SerialNumber), 2)
	log := devicesModel.DeviceLog{
		DeviceId:   deviceId,
		LogType:    devicesModel.LogProvisioned,
		LogMessage: "The device has been provisioned through the enrollment process. The new certificate Serial Number is " + serialNumber,
	}

	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return nil, err
	}

	certHistory := devicesModel.DeviceCertHistory{
		SerialNumber: serialNumber,
		DeviceId:     deviceId,
		IsuuerName:   aps,
		Status:       devicesModel.CertHistoryActive,
	}
	err = s.devicesDb.InsertDeviceCertHistory(ctx, certHistory)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceProvisioned)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, serialNumber)
	if err != nil {
		return nil, err
	}

	level.Info(s.logger).Log("msg", "Certificate sent ENROLL method")
	return dataCert, nil
}

func (s *EstService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	aps, err := s.verifyUtils.VerifyPeerCertificate(ctx, cert, false, nil)

	if err != nil {
		return nil, err
	}

	// Compare Subject fields
	if !reflect.DeepEqual(cert.Subject, csr.Subject) {
		return nil, err
	}

	deviceId := csr.Subject.CommonName
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		return nil, err
	}
	if device.Status != devicesModel.DeviceProvisioned {
		err := "Cant reenroll a device with status: " + device.Status
		return nil, errors.New(err)
	}
	currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, device.CurrentCertificate.SerialNumber)
	if err != nil {
		return nil, err
	}
	deviceCert, err := s.lamassuCaClient.GetCert(ctx, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber, "pki")

	if err != nil {
		return nil, err
	}

	certExpirationTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", deviceCert.ValidTo)
	if err != nil {
		errMsg := "Could not parse the device's cert expiration time"
		level.Debug(s.logger).Log("err", err, "msg", errMsg)
		return nil, err
	}
	fmt.Println(certExpirationTime.Date())
	fmt.Println(time.Now().Add(time.Hour * 24 * time.Duration(s.minReenrollDays)))
	if certExpirationTime.Before(time.Now().Add(time.Hour * 24 * time.Duration(s.minReenrollDays))) {

	} else {
		msg := "Cant reenroll a provisioned device before " + strconv.Itoa(s.minReenrollDays) + " days of its expiration time"
		return nil, errors.New(msg)
	}

	serialNumberToRevoke := currentCertHistory.SerialNumber
	// revoke
	err = s.lamassuCaClient.RevokeCert(ctx, currentCertHistory.IsuuerName, serialNumberToRevoke, "pki")
	if err != nil {
		errMsg := "An error ocurred while revoking the current device's cert"
		level.Error(s.logger).Log("err", err, "msg", errMsg)
		return nil, err
	}
	/*err = s.devicesDb.UpdateDeviceCertHistory(ctx, deviceId, device.CurrentCertificate.SerialNumber, devicesModel.CertHistoryRevoked)
	if err != nil {
		return nil, err
	}*/

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceCertRevoked)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, "")
	if err != nil {
		return nil, err
	}

	dataCert, err := s.lamassuCaClient.SignCertificateRequest(ctx, aps, csr, "pki", true)
	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Error in client request")
		valError := esterror.ValidationError{
			Msg: err.Error(),
		}
		return &x509.Certificate{}, &valError
	}

	deviceId = dataCert.Subject.CommonName
	serialNumber := s.verifyUtils.InsertNth(s.verifyUtils.ToHexInt(dataCert.SerialNumber), 2)
	log := devicesModel.DeviceLog{
		DeviceId:   deviceId,
		LogType:    devicesModel.LogProvisioned,
		LogMessage: "The device has been provisioned through the enrollment process. The new certificate Serial Number is " + serialNumber,
	}

	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return nil, err
	}

	certHistory := devicesModel.DeviceCertHistory{
		SerialNumber: serialNumber,
		DeviceId:     deviceId,
		IsuuerName:   aps,
		Status:       devicesModel.CertHistoryActive,
	}
	err = s.devicesDb.InsertDeviceCertHistory(ctx, certHistory)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceProvisioned)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, serialNumber)
	if err != nil {
		return nil, err
	}

	return dataCert, nil
}
func (s *EstService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	csrkey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privkey, err := x509.MarshalPKCS8PrivateKey(csrkey)
	if err != nil {
		return nil, nil, err
	}

	deviceId := csr.Subject.CommonName
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		return nil, nil, err
	}

	if device.Status == devicesModel.DeviceDecommisioned {
		err := "Cant issue a certificate for a decommisioned device"
		return nil, nil, errors.New(err)
	}

	if device.Status == devicesModel.DeviceProvisioned {
		return nil, nil, errors.New("The device (" + deviceId + ") already has a valid certificate")
	}

	csr, err = s.verifyUtils.GenerateCSR(csr, csrkey)
	if err != nil {
		return nil, nil, err
	}

	dataCert, err := s.lamassuCaClient.SignCertificateRequest(ctx, aps, csr, "pki", true)
	if err != nil {
		level.Debug(s.logger).Log("err", err, "msg", "Error in client request")
		valError := esterror.ValidationError{
			Msg: err.Error(),
		}
		return &x509.Certificate{}, nil, &valError
	}

	deviceId = dataCert.Subject.CommonName
	serialNumber := s.verifyUtils.InsertNth(s.verifyUtils.ToHexInt(dataCert.SerialNumber), 2)
	log := devicesModel.DeviceLog{
		DeviceId:   deviceId,
		LogType:    devicesModel.LogProvisioned,
		LogMessage: "The device has been provisioned through the enrollment process. The new certificate Serial Number is " + serialNumber,
	}

	err = s.devicesDb.InsertLog(ctx, log)
	if err != nil {
		return nil, nil, err
	}

	certHistory := devicesModel.DeviceCertHistory{
		SerialNumber: serialNumber,
		DeviceId:     deviceId,
		IsuuerName:   aps,
		Status:       devicesModel.CertHistoryActive,
	}
	err = s.devicesDb.InsertDeviceCertHistory(ctx, certHistory)
	if err != nil {
		return nil, nil, err
	}

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceProvisioned)
	if err != nil {
		return nil, nil, err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, serialNumber)
	if err != nil {
		return nil, nil, err
	}

	return dataCert, privkey, nil
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

func (s *EstService) getCaName(ctx context.Context, serialNumber string) (string, error) {
	CAs, err := s.lamassuCaClient.GetCAs(ctx, "pki")
	if err != nil {
		return "", err
	}

	for _, CA := range CAs.Certs {
		if serialNumber == CA.SerialNumber || serialNumber == CA.CAName {
			return CA.CAName, err
		}
	}
	return "", err
}

func (s *EstService) verifyCaName(ctx context.Context, caname string, dmsDB dmsStore.DB, dmsid string) (string, error) {
	dmsCas, err := s.dmsDb.SelectByDMSIDAuthorizedCAs(ctx, dmsid)
	if err != nil {
		return "", err
	}
	for _, dmsCa := range dmsCas {
		if caname == dmsCa.CaName {
			return caname, nil
		}
	}
	return "", nil
}
