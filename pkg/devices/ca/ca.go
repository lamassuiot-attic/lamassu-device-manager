package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/api"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
	devicesStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device/store"
	"github.com/lamassuiot/lamassu-est/configs"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/est"
	"github.com/lamassuiot/lamassu-est/client/estclient"
)

type DeviceEstService struct {
	devicesDb            devicesStore.DB
	logger               log.Logger
	caClient             *http.Client
	caUrl                string
	keycloakClient       *http.Client
	keycloakUrl          string
	keycloakClientId     string
	keycloakClientSecret string
	minReenrollDays      int
}

func NewEstService(devicesDb devicesStore.DB, caClient *http.Client, caUrl string, keycloakClient *http.Client, keycloakUrl string, keycloakClientId string, keycloakClientSecret string, minReenrollDays int, logger log.Logger) *DeviceEstService {
	return &DeviceEstService{
		devicesDb:            devicesDb,
		caUrl:                caUrl,
		caClient:             caClient,
		keycloakClient:       keycloakClient,
		keycloakUrl:          keycloakUrl,
		keycloakClientId:     keycloakClientId,
		keycloakClientSecret: keycloakClientSecret,
		minReenrollDays:      minReenrollDays,
		logger:               logger,
	}
}

func (ca *DeviceEstService) CACerts(ctx context.Context, aps string, req *http.Request) ([]*x509.Certificate, error) {

	var filteredCerts []*x509.Certificate

	configStr, err := configs.NewConfigEnvClient("est")
	if err != nil {
		fmt.Errorf("failed to laod env variables %v", err)
	}

	cfg, err := configs.NewConfig(configStr)
	if err != nil {
		fmt.Errorf("failed to make EST client's configurations: %v", err)
	}

	client, err := estclient.NewClient(cfg)

	filteredCerts, err = client.GetCAs(aps)
	if err != nil {
		return nil, err
	}

	return filteredCerts, nil
}

func (ca *DeviceEstService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	deviceId := csr.Subject.CommonName
	device, err := ca.devicesDb.SelectDeviceById(deviceId)
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

	configStr, err := configs.NewConfigEnvClient("est")
	if err != nil {
		fmt.Errorf("failed to laod env variables %v", err)
	}

	cfg, err := configs.NewConfig(configStr)
	if err != nil {
		fmt.Errorf("failed to make EST client's configurations: %v", err)
	}

	client, err := estclient.NewClient(cfg)

	cert, err := client.Enroll(csr, aps)
	if err != nil {
		return nil, err
	}

	deviceId = cert.Subject.CommonName
	serialNumber := insertNth(toHexInt(cert.SerialNumber), 2)
	log := devicesModel.DeviceLog{
		DeviceId:   deviceId,
		LogType:    devicesModel.LogProvisioned,
		LogMessage: "The device has been provisioned through the enrollment process. The new certificate Serial Number is " + serialNumber,
	}
	err = ca.devicesDb.InsertLog(log)
	if err != nil {
		return nil, err
	}

	certHistory := devicesModel.DeviceCertHistory{
		SerialNumber: serialNumber,
		DeviceId:     deviceId,
		IsuuerName:   aps,
		Status:       devicesModel.CertHistoryActive,
	}
	err = ca.devicesDb.InsertDeviceCertHistory(certHistory)
	if err != nil {
		return nil, err
	}

	err = ca.devicesDb.UpdateDeviceStatusByID(deviceId, devicesModel.DeviceProvisioned)
	if err != nil {
		return nil, err
	}

	err = ca.devicesDb.UpdateDeviceCertificateSerialNumberByID(deviceId, serialNumber)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (ca *DeviceEstService) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{}, nil
}

func (ca *DeviceEstService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	deviceId := csr.Subject.CommonName
	device, err := ca.devicesDb.SelectDeviceById(deviceId)
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
	var devicesService api.Service
	{
		devicesService = api.NewDevicesService(ca.devicesDb, ca.caClient, ca.caUrl, ca.keycloakClient, ca.keycloakUrl, ca.keycloakClientId, ca.keycloakClientSecret)
		devicesService = api.LoggingMiddleware(ca.logger)(devicesService)
	}
	retrievedDeviceCert, err := devicesService.GetDeviceCert(ctx, cert.Subject.CommonName)
	if err != nil {
		errMsg := "An error ocurred while trying to fetch the current device's cert"
		//level.Error(ca.logger).Log("err", err, "msg", errMsg)
		fmt.Println(errMsg)
		return nil, errors.New(errMsg)
	}

	certExpirationTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", retrievedDeviceCert.ValidTo)
	if err != nil {
		errMsg := "Could not parse the device's cert expiration time"
		level.Error(ca.logger).Log("err", err, "msg", errMsg)
		return nil, errors.New(errMsg)
	}

	// fmt.Println(certExpirationTime)
	// fmt.Println(time.Now().Add(time.Hour * 24 * time.Duration(ca.minReenrollDays)))
	// fmt.Println(certExpirationTime.Before(time.Now().Add(time.Hour * 24 * time.Duration(ca.minReenrollDays))))
	if certExpirationTime.Before(time.Now().Add(time.Hour * 24 * time.Duration(ca.minReenrollDays))) {
		msg := "Reenrolling device"
		fmt.Println(msg)
	} else {
		msg := "Cant reenroll a provisioned device before " + strconv.Itoa(ca.minReenrollDays) + " days of its expiration time"
		fmt.Println(msg)
		return nil, errors.New(msg)
	}

	err = devicesService.RevokeDeviceCert(ctx, cert.Subject.CommonName, "Revocation due to reenrollment")
	if err != nil {
		errMsg := "An error ocurred while revoking the current device's cert"
		level.Error(ca.logger).Log("err", err, "msg", errMsg)
		return nil, errors.New(errMsg)
	}

	configStr, err := configs.NewConfigEnvClient("est")
	if err != nil {
		fmt.Errorf("failed to laod env variables %v", err)
	}

	cfg, err := configs.NewConfig(configStr)
	if err != nil {
		fmt.Errorf("failed to make EST client's configurations: %v", err)
	}

	client, err := estclient.NewClient(cfg)

	crt, err := client.Enroll(csr, aps)
	if err != nil {
		return nil, err
	}

	deviceId = crt.Subject.CommonName
	serialNumber := insertNth(toHexInt(cert.SerialNumber), 2)
	log := devicesModel.DeviceLog{
		DeviceId:   deviceId,
		LogType:    devicesModel.LogProvisioned,
		LogMessage: "The device has been provisioned through the re-enrollment process. The new certificate Serial Number is " + serialNumber,
	}
	err = ca.devicesDb.InsertLog(log)
	if err != nil {
		return nil, err
	}
	//Check if the device previously had a certificate with the same serial number
	_, err = ca.devicesDb.SelectDeviceCertHistoryBySerialNumber(serialNumber)
	if err != nil {
		certHistory := devicesModel.DeviceCertHistory{
			SerialNumber: serialNumber,
			DeviceId:     deviceId,
			IsuuerName:   aps,
			Status:       devicesModel.CertHistoryActive,
		}
		err = ca.devicesDb.InsertDeviceCertHistory(certHistory)
		if err != nil {
			return nil, err
		}
	} else {
		ca.devicesDb.UpdateDeviceCertHistory(deviceId, serialNumber, devicesModel.CertHistoryActive)
	}

	err = ca.devicesDb.UpdateDeviceStatusByID(deviceId, devicesModel.DeviceProvisioned)
	if err != nil {
		return nil, err
	}

	err = ca.devicesDb.UpdateDeviceCertificateSerialNumberByID(deviceId, serialNumber)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

func (ca *DeviceEstService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, nil
}

func (ca *DeviceEstService) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

func toHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n) // or %X or upper case
}

func insertNth(s string, n int) string {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune('-')
		}
	}
	return buffer.String()
}
