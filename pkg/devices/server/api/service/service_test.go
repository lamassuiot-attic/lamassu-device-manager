package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/go-kit/kit/log"

	//lamassucaclient "github.com/lamassuiot/lamassu-ca/client"
	//"github.com/lamassuiot/lamassu-device-manager/pkg/devices/configs"
	lamassucaclient "github.com/lamassuiot/lamassu-ca/pkg/client"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/mocks"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device"
	devicesStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/models/device/store"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/utils"
)

type serviceSetUp struct {
	devicesDb       devicesStore.DB
	logger          log.Logger
	lamassuCaClient lamassucaclient.LamassuCaClient
}

func TestHealth(t *testing.T) {
	srv, ctx := setup(t)
	type testCasesHealth struct {
		name string
		ret  bool
	}
	cases := []testCasesHealth{
		{"Correct", true},
	}
	for _, tc := range cases {

		out := srv.Health(ctx)
		if tc.ret != out {
			t.Errorf("Expected '%s', but got '%s'", strconv.FormatBool(tc.ret), strconv.FormatBool(out))
		}

	}
}

func TestGetDeviceCert(t *testing.T) {
	srv, ctx := setup(t)
	/*subject := devicesModel.Subject{
		C:  "ES",
		ST: "Guipuzcoa",
		L:  "Mondragon",
		O:  "Ikerlan",
		OU: "ZPD",
		CN: "testDeviceMock",
	}
	key := devicesModel.PrivateKeyMetadata{
		KeyType: "rsa",
		KeyBits: 3072,
	}
	dNoSerialNumer, _ := srv.PostDevice(ctx, "noSN", "noSN", 1, key, subject)*/
	d := testGetDeviceCert()
	dErrorId := d
	dErrorId.DeviceId = "errorDeviceById"
	dErrorEmptySerialNumber := d
	dErrorEmptySerialNumber.SerialNumber = ""

	testCases := []struct {
		name string
		id   string
		res  devicesModel.DeviceCert
		ret  error
	}{
		{"Error getting cert", "error", d, errors.New("Error getting certificate")},
		{"Error finding device", "errorDeviceById", dErrorId, errors.New("Could not find device by Id")},
		{"Error empty serial number", "noSerialNumber", dErrorEmptySerialNumber, errors.New("No Serial Number")},
		{"Error certificate history could not find", "error", d, errors.New("Testing DB connection failed")},
		{"Correct", "1", d, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error certificate history could not find" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
			} else if tc.name == "Error getting cert" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
			}
			_, err := srv.GetDeviceCert(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}

		})
	}
}

func TestGetKeyStrength(t *testing.T) {
	//srv, _ := setup(t)
	type testCases struct {
		keyType string
		keyBits int
		ret     string
	}
	cases := []testCases{
		{"rsa", 2, "low"},
		{"rsa", 3070, "medium"},
		{"rsa", 10000, "high"},
		{"ec", 2, "low"},
		{"ec", 250, "medium"},
		{"ec", 1000, "high"},
	}
	for _, tc := range cases {

		out := getKeyStrength(tc.keyType, tc.keyBits)
		if tc.ret != out {
			t.Errorf("Expected '%s', but got '%s'", tc.ret, out)
		}

	}
}

func TestGenerateCSR(t *testing.T) {
	_, ctx := setup(t)
	var p1 interface{}

	testCases := []struct {
		name    string
		keyType string
		ret     error
	}{
		{"Empty priv", "ecdsa", errors.New("x509: certificate private key does not implement crypto.Signer")},
		{"Empty priv", "rsa", errors.New("x509: certificate private key does not implement crypto.Signer")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			_, err := _generateCSR(ctx, tc.keyType, p1, "commonName", "country", "state", "locality", "org", "orgUnit")
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestGetDevices(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  error
	}{
		{"Correct", nil},
		{"Error getting devices", errors.New("Testing DB connection failed")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error getting devices" {
				ctx = context.WithValue(ctx, "DBShouldFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
			}
			_, err := srv.GetDevices(ctx)
			if err != nil {
				if tc.ret.Error() != err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}

			}
		})
	}
}

func TestGetDeviceById(t *testing.T) {
	srv, ctx := setup(t)
	d := testDevice()

	testCases := []struct {
		name string
		id   string
		res  devicesModel.Device
		ret  error
	}{
		{"Incorrect", "errorDeviceById", d, errors.New("Could not find device by Id")},
		{"Correct", "1", d, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDeviceById(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
			if err == nil {
				if out != tc.res {
					t.Errorf("Got result is diferent from expected response")
				}
			}
		})
	}
}

func TestGetDevicesByDMS(t *testing.T) {
	srv, ctx := setup(t)

	d := testDevice()
	var devList []devicesModel.Device
	key := devicesModel.PrivateKeyMetadata{
		KeyType: "rsa",
		KeyBits: 3072,
	}
	dev, _ := srv.PostDevice(ctx, d.Alias, d.Id, d.DmsId, key, d.Subject)
	devList = append(devList, dev)

	testCases := []struct {
		name  string
		dmsId string
		res   []devicesModel.Device
		ret   error
	}{
		{"Incorrect", "error", devList, errors.New("Could not find device by Id")},
		{"Correct", "1", devList, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			_, err := srv.GetDevicesByDMS(ctx, tc.dmsId)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestGetDeviceLogs(t *testing.T) {
	srv, ctx := setup(t)

	logs := testDeviceLogs()
	var logArray []devicesModel.DeviceLog

	testCases := []struct {
		name string
		id   string
		res  []devicesModel.DeviceLog
		ret  error
	}{
		{"Incorrect", "errorGetDeviceLogs", logArray, errors.New("err")},
		{"Correct", "1", logs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDeviceLogs(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
			if err == nil {
				if len(out) > 0 && len(tc.res) > 0 {
					if out[0] != tc.res[0] {
						t.Errorf("Got result is diferent from expected response")
					}
				}

			}
		})
	}
}

func TestGetDeviceCertHistory(t *testing.T) {
	srv, ctx := setup(t)
	certs := testGetDeviceCertHistory()

	testCases := []struct {
		name string
		id   string
		res  []devicesModel.DeviceCertHistory
		ret  error
	}{
		{"Error Device Certification History", "error", certs, errors.New("Testing DB connection failed")},
		{"Correct", "1", certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Device Certification History" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
			}
			_, err := srv.GetDeviceCertHistory(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}

		})
	}
}

func TestGetDmsCertHistoryThirtyDays(t *testing.T) {
	srv, ctx := setup(t)

	certs := testDMSCertsHistory()
	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		id   string
		res  []devicesModel.DMSCertHistory
		ret  error
	}{
		{"Error Get Devices", "error", certs, errors.New("Testing DB connection failed")},
		{"Error getting historial 30 days", "error", certs, errors.New("Testing DB connection failed")},
		{"Correct", "1", certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error getting historial 30 days" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", true)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
			} else if tc.name == "Error Get Devices" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "DBShouldFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
			}
			_, err := srv.GetDmsCertHistoryThirtyDays(ctx)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}

			}

		})
	}
}

func TestGetDmsLastIssuedCert(t *testing.T) {
	srv, ctx := setup(t)

	certs := testDmsLastIssuedCert()

	testCases := []struct {
		name string
		res  []devicesModel.DMSLastIssued
		ret  error
	}{
		{"Error last issued cert not found", certs, errors.New("Testing DB connection failed")},
		{"Correct", certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error last issued cert not found" {
				ctx = context.WithValue(ctx, "DBSelectDmssLastIssuedCert", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDmssLastIssuedCert", false)
			}
			_, err := srv.GetDmsLastIssuedCert(ctx)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}

			}

		})
	}
}

func TestRevokeDeviceCert(t *testing.T) {
	srv, ctx := setup(t)

	d := testDevice()
	key := devicesModel.PrivateKeyMetadata{
		KeyType: "rsa",
		KeyBits: 3072,
	}
	srv.PostDevice(ctx, d.Alias, d.Id, d.DmsId, key, d.Subject)
	dNoSerialNumber := testDeviceNoSerialNumber()

	srv.PostDevice(ctx, dNoSerialNumber.Alias, dNoSerialNumber.Id, dNoSerialNumber.DmsId, key, dNoSerialNumber.Subject)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Error finding device", "errorDeviceById", errors.New("Could not find device by Id")},
		{"Error inserting log", "errorLog", errors.New("Could not insert log")},
		{"Error empty serial number", "noSerialNumber", errors.New("No Serial Number")},
		{"Error could not revoke certificate", "errorRevokeCert", errors.New("Error revoking certificate")},
		{"Error updating certificate history", "errorUpdateDeviceCertHistory", errors.New("error")},
		{"Error updating certificate history serial number", "errorUpdateDeviceCertificateSerialNumberByID", errors.New("error")},
		{"Error updating device status", "errorUpdateStatus", errors.New("error")},
		{"Error certificate history could not find", "error", errors.New("Testing DB connection failed")},

		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error certificate history could not find" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)

			} else if tc.name == "Error could not revoke certificate" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			}
			err := srv.RevokeDeviceCert(ctx, tc.id, "Manual revocation")

			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestPostDevice(t *testing.T) {
	srv, ctx := setup(t)

	device := testDevice()
	deviceError := testDevice()
	deviceError.Id = "error"
	deviceErrorLog := device
	deviceErrorLog.Id = "errorLog"
	deviceErrorDeviceByID := device
	deviceErrorDeviceByID.Id = "errorDeviceById"

	testCases := []struct {
		name string
		in   devicesModel.Device
		err  error
	}{
		{"Correct device", device, nil},
		{"Error Inserting Log", deviceErrorLog, errors.New("Could not insert log")},
		{"Error Inserting Device", deviceError, errors.New("error")},
		{"Error Finding Device", deviceErrorDeviceByID, errors.New("Could not find device by Id")},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			key := devicesModel.PrivateKeyMetadata{
				KeyType: "rsa",
				KeyBits: 3072,
			}
			out, err := srv.PostDevice(ctx, tc.in.Alias, tc.in.Id, tc.in.DmsId, key, tc.in.Subject)
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			} else {
				if tc.in.Id != out.Id {
					t.Errorf("Not receiving expected response")
				}
			}
		})
	}
}

func TestDeleteDevice(t *testing.T) {
	srv, ctx := setup(t)

	d := testDevice()
	key := devicesModel.PrivateKeyMetadata{
		KeyType: "rsa",
		KeyBits: 3072,
	}
	srv.PostDevice(ctx, d.Alias, d.Id, d.DmsId, key, d.Subject)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Error finding device", "error", errors.New("test")},
		{"Error inserting log", "errorLog", errors.New("Could not insert log")},
		{"Error empty serial number", "error", errors.New("test")},
		{"Error could not revoke certificate", "errorRevokeCert", errors.New("test")},
		{"Error updating certificate history", "errorUpdateDeviceCertHistory", errors.New("test")},
		{"Error updating certificate history serial number", "errorUpdateDeviceCertificateSerialNumberByID", errors.New("test")},
		{"Error updating device status", "errorUpdateStatus", errors.New("error")},
		{"Error certificate history could not find", "error", errors.New("test")},

		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error updating device status" {
				ctx = context.WithValue(ctx, "DBShouldFail", true)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)

			} else if tc.name == "Error certificate history could not find" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			}
			err := srv.DeleteDevice(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func testDevice() devicesModel.Device {
	subject := devicesModel.Subject{
		C:  "ES",
		ST: "Guipuzcoa",
		L:  "Mondragon",
		O:  "Ikerlan",
		OU: "ZPD",
		CN: "testDeviceMock",
	}
	key := devicesModel.PrivateKeyMetadataWithStregth{
		KeyType:     "rsa",
		KeyBits:     3072,
		KeyStrength: "",
	}
	device := devicesModel.Device{
		Id:                      "1",
		Alias:                   "testDeviceMock",
		Status:                  "CERT_REVOKED",
		DmsId:                   1,
		Subject:                 subject,
		KeyMetadata:             key,
		CreationTimestamp:       "2022-01-11T07:02:40.082286Z",
		CurrentCertSerialNumber: "23-33-5b-19-c8-ed-8b-2a-92-5c-7b-57-fc-47-45-e7-12-03-91-23",
	}

	return device
}

func testDeviceNoSerialNumber() devicesModel.Device {
	subject := devicesModel.Subject{
		C:  "ES",
		ST: "Guipuzcoa",
		L:  "Mondragon",
		O:  "Ikerlan",
		OU: "ZPD",
		CN: "testDeviceMock",
	}
	key := devicesModel.PrivateKeyMetadataWithStregth{
		KeyType:     "rsa",
		KeyBits:     3072,
		KeyStrength: "",
	}
	device := devicesModel.Device{
		Id:                      "noSN",
		Alias:                   "noSN",
		Status:                  "CERT_REVOKED",
		DmsId:                   1,
		Subject:                 subject,
		KeyMetadata:             key,
		CreationTimestamp:       "2022-01-11T07:02:40.082286Z",
		CurrentCertSerialNumber: "",
	}

	return device
}

func testDeviceLogs() []devicesModel.DeviceLog {

	var logList []devicesModel.DeviceLog
	log := devicesModel.DeviceLog{
		Id:         "1",
		DeviceId:   "1",
		LogType:    "",
		LogMessage: "",
		Timestamp:  "",
	}
	logList = append(logList, log)
	return logList
}

type Subject struct {
	CN string `json:"common_name"`
	O  string `json:"organization"`
	OU string `json:"organization_unit"`
	C  string `json:"country"`
	ST string `json:"state"`
	L  string `json:"locality"`
}

func testGetDeviceCert() devicesModel.DeviceCert {

	subject := devicesModel.Subject{
		C:  "",
		ST: "",
		L:  "",
		O:  "",
		OU: "",
		CN: "",
	}
	log := devicesModel.DeviceCert{
		DeviceId:     "1",
		SerialNumber: "",
		CAName:       "",
		Status:       "",
		CRT:          "",
		Subject:      subject,
		ValidFrom:    "",
		ValidTo:      "",
	}
	return log
}

func testGetDeviceCertHistory() []devicesModel.DeviceCertHistory {

	var certList []devicesModel.DeviceCertHistory
	cert := devicesModel.DeviceCertHistory{

		DeviceId:           "1",
		SerialNumber:       "",
		IssuerSerialNumber: "",
		IsuuerName:         "",
		Status:             "",
		CreationTimestamp:  "",
	}
	certList = append(certList, cert)
	return certList
}

func testDMSCertsHistory() []devicesModel.DMSCertHistory {

	var certList []devicesModel.DMSCertHistory
	cert := devicesModel.DMSCertHistory{
		DmsId:       1,
		IssuedCerts: 1,
	}
	certList = append(certList, cert)
	return certList
}

func testDmsLastIssuedCert() []devicesModel.DMSLastIssued {

	var certList []devicesModel.DMSLastIssued
	cert := devicesModel.DMSLastIssued{
		DmsId:        1,
		Timestamp:    "",
		SerialNumber: "",
	}
	certList = append(certList, cert)

	return certList
}

func setup(t *testing.T) (Service, context.Context) {
	t.Helper()

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	ctx := context.Background()
	ctx = context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)

	devicesDb, _ := mocks.NewDevicedDBMock(t)

	lamassuCaClient, _ := mocks.NewLamassuCaClientMock(logger)

	srv := NewDevicesService(devicesDb, &lamassuCaClient, logger)
	return srv, ctx
}
