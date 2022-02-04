package estserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"

	"github.com/go-kit/log/level"
	lamassuca "github.com/lamassuiot/lamassu-ca/client"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
	devicesStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device/store"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/utils"
	lamassuest "github.com/lamassuiot/lamassu-est/pkg/server/api"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type EstService struct {
	logger          log.Logger
	lamassuCaClient lamassuca.LamassuCaClient
	verifyUtils     utils.Utils
	devicesDb       devicesStore.DB
	minReenrollDays int
}

func NewEstService(lamassuCaClient *lamassuca.LamassuCaClient, verifyUtils *utils.Utils, devicesDb devicesStore.DB, minReenrollDays int, logger log.Logger) lamassuest.Service {

	return &EstService{
		lamassuCaClient: *lamassuCaClient,
		logger:          logger,
		verifyUtils:     *verifyUtils,
		devicesDb:       devicesDb,
		minReenrollDays: minReenrollDays,
	}
}

func (s *EstService) Health(ctx context.Context) bool {
	return true
}

func (s *EstService) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {
	certs, err := s.lamassuCaClient.GetCAs(ctx, "pki")
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Error in client request")
		return nil, err
	}

	x509Certificates := []*x509.Certificate{}
	for _, v := range certs.Certs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		cert, _ := x509.ParseCertificate(block.Bytes)
		x509Certificates = append(x509Certificates, cert)
	}
	level.Info(s.logger).Log("msg", "Certificates sent CACerts method")
	return x509Certificates, nil
}

func (s *EstService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate, r *http.Request) (*x509.Certificate, error) {
	aps, err := s.verifyUtils.VerifyPeerCertificate(ctx, cert, false, nil)

	if err != nil {
		return nil, err
	}
	if aps == "" {
		return nil, lamassuest.ErrInvalidAPS
	}

	// Compare Subject fields
	if !reflect.DeepEqual(cert.Subject, csr.Subject) {
		return nil, lamassuest.ErrSubjectChanged
	}

	// Compare SubjectAltName fields
	var csrSAN pkix.Extension
	var certSAN pkix.Extension

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			csrSAN = ext
			break
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			certSAN = ext
			break
		}
	}

	if !bytes.Equal(csrSAN.Value, certSAN.Value) {
		return nil, lamassuest.ErrSubjectChanged

	}

	deviceId := csr.Subject.CommonName
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			fmt.Println("Device " + deviceId + " does not exist. Register the device first, and enroll it afterwards")
		}
		return nil, err
	}

	if device.Status == devicesModel.DeviceDecommisioned {
		err := "Cant issue a certificate for a decommisioned device"
		fmt.Println(err)
		return nil, errors.New(err)
	}

	if device.Status == devicesModel.DeviceProvisioned {
		err := "The device (" + deviceId + ") already has a valid certificate"
		fmt.Println(err)
		return nil, errors.New(err)
	}

	dataCert, err := s.lamassuCaClient.SignCertificateRequest(ctx, aps, csr, "pki")
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Error in client request")
		return &x509.Certificate{}, err
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

	level.Info(s.logger).Log("msg", "Certificate sent ENROLL method")
	return dataCert, nil
}

func (s *EstService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {

	deviceId := csr.Subject.CommonName
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			fmt.Println("Device " + deviceId + " does not exist. Register the device first, and enroll it afterwards")
		}
		return nil, err
	}
	if device.Status != devicesModel.DeviceProvisioned {
		err := "Cant reenroll a device with status: " + device.Status
		fmt.Println(err)
		return nil, errors.New(err)
	}
	currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, device.CurrentCertSerialNumber)
	if err != nil {
		return nil, err
	}
	deviceCert, err := s.lamassuCaClient.GetCert(ctx, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber, "pki")

	if err != nil {
		errMsg := "An error ocurred while trying to fetch the current device's cert"
		//level.Error(ca.logger).Log("err", err, "msg", errMsg)
		fmt.Println(errMsg)
		return nil, errors.New(errMsg)
	}

	certExpirationTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", deviceCert.ValidTo)
	if err != nil {
		errMsg := "Could not parse the device's cert expiration time"
		level.Error(s.logger).Log("err", err, "msg", errMsg)
		return nil, errors.New(errMsg)
	}

	if certExpirationTime.Before(time.Now().Add(time.Hour * 24 * time.Duration(s.minReenrollDays))) {
		msg := "Reenrolling device"
		fmt.Println(msg)
	} else {
		msg := "Cant reenroll a provisioned device before " + strconv.Itoa(s.minReenrollDays) + " days of its expiration time"
		fmt.Println(msg)
		return nil, errors.New(msg)
	}

	serialNumberToRevoke := currentCertHistory.SerialNumber
	// revoke
	err = s.lamassuCaClient.RevokeCert(ctx, currentCertHistory.IsuuerName, serialNumberToRevoke, "pki")
	if err != nil {
		errMsg := "An error ocurred while revoking the current device's cert"
		level.Error(s.logger).Log("err", err, "msg", errMsg)
		return nil, errors.New(errMsg)
	}
	if err != nil {
		errMsg := "An error ocurred while trying to fetch the current device's cert"
		//level.Error(ca.logger).Log("err", err, "msg", errMsg)
		fmt.Println(errMsg)
		return nil, errors.New(errMsg)
	}

	dataCert, err := s.lamassuCaClient.SignCertificateRequest(ctx, aps, csr, "pki")
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Error in client request")
		return &x509.Certificate{}, err
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

	level.Info(s.logger).Log("msg", "Certificate sent REENROLL method")
	return dataCert, nil
}
func (s *EstService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	csrkey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate temporary private key: %v", err)
	}
	privkey, err := x509.MarshalPKCS8PrivateKey(csrkey)
	if err != nil {
		return nil, nil, err
	}

	deviceId := csr.Subject.CommonName
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			fmt.Println("Device " + deviceId + " does not exist. Register the device first, and enroll it afterwards")
		}
		return nil, nil, err
	}

	if device.Status == devicesModel.DeviceDecommisioned {
		err := "Cant issue a certificate for a decommisioned device"
		fmt.Println(err)
		return nil, nil, errors.New(err)
	}

	if device.Status == devicesModel.DeviceProvisioned {
		err := "The device (" + deviceId + ") already has a valid certificate"
		fmt.Println(err)
		return nil, nil, errors.New(err)
	}

	csr, err = s.verifyUtils.GenerateCSR(csr, csrkey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new csr: %v", err)
	}

	dataCert, err := s.lamassuCaClient.SignCertificateRequest(ctx, aps, csr, "pki")
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Error in client request")
		return &x509.Certificate{}, nil, err
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

	level.Info(s.logger).Log("msg", "Certificate and key sent ServerKeyGen method")
	return dataCert, privkey, nil
}
