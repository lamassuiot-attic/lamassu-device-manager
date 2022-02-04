package api

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"

	lamassucaclient "github.com/lamassuiot/lamassu-ca/client"
	mocksCA "github.com/lamassuiot/lamassu-ca/pkg/mocks"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/configs"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/mocks"
	devicesModel "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device"
	devicesStore "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device/store"
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
func TestPostDevice(t *testing.T) {
	srv, ctx := setup(t)

	device := testDevice()

	testCases := []struct {
		name   string
		newDev devicesModel.Device
		ret    devicesModel.Device
		err    error
	}{
		{"Correct device", device, device, nil},
		//{"Create empty device", devicesModel.Device{},devicesModel.Device{}, ErrEmptyDevice},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			_, err := srv.PostDevice(ctx, device)
			if tc.ret != tc.newDev {
				t.Errorf("Got result is different of created CA")
			}
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			}
		})
	}
}
func TestGetDevices(t *testing.T) {
	srv, ctx := setup(t)

	var Devices devicesModel.Devices
	var devList []devicesModel.Device
	dev, _ := srv.PostDevice(ctx, testDevice())
	devList = append(devList, dev)
	Devices = devicesModel.Devices{Devices: devList}

	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		res  devicesModel.Devices
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", Devices, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDevices(ctx)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.Devices) != len(out.Devices) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.Devices) > 0 {
					for i := 0; i < len(tc.res.Devices); i++ {
						if tc.res.Devices[i] != out.Devices[i] {
							t.Errorf("CA has not the same certs than expected")
						}
					}
				}
			}
		})
	}
}
func TestGetDeviceById(t *testing.T) {
	srv, ctx := setup(t)

	dev, _ := srv.PostDevice(ctx, testDevice())

	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		id   string
		res  devicesModel.Device
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", "1", dev, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDeviceById(ctx, tc.id)
			if err != nil {
				if out.Id != tc.res.Id {
					t.Errorf("Expected '%s', but got '%s'", tc.res.Id, out.Id)
				}
			}
		})
	}
}
func TestGetDevicesByDMS(t *testing.T) {
	srv, ctx := setup(t)

	var Devices devicesModel.Devices
	var devList []devicesModel.Device
	dev, _ := srv.PostDevice(ctx, testDevice())
	devList = append(devList, dev)
	Devices = devicesModel.Devices{Devices: devList}
	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name  string
		dmsId string
		res   devicesModel.Devices
		ret   error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", "1", Devices, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDevicesByDMS(ctx, tc.dmsId)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.Devices) != len(out.Devices) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.Devices) > 0 {
					for i := 0; i < len(tc.res.Devices); i++ {
						if tc.res.Devices[i].DmsId != out.Devices[i].DmsId {
							t.Errorf("CA has not the same certs than expected")
						}
					}
				}
			}
		})
	}
}
func TestDeleteDevice(t *testing.T) {
	srv, ctx := setup(t)

	srv.PostDevice(ctx, testDevice())

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		//{"Delete non existing", "2", ErrGetCAs},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			err := srv.DeleteDevice(ctx, tc.id)
			if err != nil {

				t.Errorf("Expected '%s', but got '%s'", tc.ret, err)

			}
		})
	}
}
func TestRevokeDeviceCert(t *testing.T) {
	srv, ctx := setup(t)

	srv.PostDevice(ctx, testDevice())

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		//{"Delete non existing", "2", ErrGetCAs},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			err := srv.RevokeDeviceCert(ctx, tc.id, "Manual revocation")

			if err != nil {

				t.Errorf("Expected '%s', but got '%s'", tc.ret, err)

			}
		})
	}
}


func TestGetDeviceLogs(t *testing.T) {
	srv, ctx := setup(t)

	logs := testDeviceLogs()
	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		id   string
		res  devicesModel.DeviceLogs
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", "1", logs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDeviceLogs(ctx, tc.id)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.Logs) != len(out.Logs) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.Logs) > 0 {
					for i := 0; i < len(tc.res.Logs); i++ {
						if tc.res.Logs[i].Id != out.Logs[i].Id {
							t.Errorf("CA has not the same certs than expected")
						}
					}
				}
			}
		})
	}
}

func TestGetDeviceCert(t *testing.T) {
	srv, ctx := setup(t)

	certs := testGetDeviceCert()
	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		id   string
		res  devicesModel.DeviceCert
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", "1", certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDeviceCert(ctx, tc.id)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if out.DeviceId != tc.res.DeviceId {
					t.Errorf("Expected '%s', but got '%s'", tc.res.DeviceId, out.DeviceId)
				}
				
			}
		})
	}
}


func TestGetDeviceCertHistory(t *testing.T) {
	srv, ctx := setup(t)

	certs := testGetDeviceCertHistory()
	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		id   string
		res  devicesModel.DeviceCertsHistory
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", "1", certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDeviceCertHistory(ctx, tc.id)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.DeviceCertHistory) != len(out.DeviceCertHistory) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.DeviceCertHistory) > 0 {
					for i := 0; i < len(tc.res.DeviceCertHistory); i++ {
						if tc.res.DeviceCertHistory[i].DeviceId != out.DeviceCertHistory[i].DeviceId {
							t.Errorf("CA has not the same certs than expected")
						}
					}
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
		res  devicesModel.DMSCertsHistory
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", "1", certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDmsCertHistoryThirtyDays(ctx)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.DMSCertsHistory) != len(out.DMSCertsHistory) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.DMSCertsHistory) > 0 {
					for i := 0; i < len(tc.res.DMSCertsHistory); i++ {
						if tc.res.DMSCertsHistory[i].DmsId != out.DMSCertsHistory[i].DmsId {
							t.Errorf("CA has not the same certs than expected")
						}
					}
				}
			}
		})
	}
}

func TestGetDmsLastIssuedCert(t *testing.T) {
	srv, ctx := setup(t)

	certs := testDmsLastIssuedCert()
	//var CAEmptys devicesModel.Devices

	testCases := []struct {
		name string
		res  devicesModel.DMSsLastIssued
		ret  error
	}{
		//{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct",  certs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			out, err := srv.GetDmsLastIssuedCert(ctx)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.DMSLastIssued) != len(out.DMSLastIssued) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.DMSLastIssued) > 0 {
					for i := 0; i < len(tc.res.DMSLastIssued); i++ {
						if tc.res.DMSLastIssued[i].DmsId != out.DMSLastIssued[i].DmsId {
							t.Errorf("CA has not the same certs than expected")
						}
					}
				}
			}
		})
	}
}



func testDevice() devicesModel.Device {
	device := devicesModel.Device{
		Id:                      "device",
		Alias:                   "testDeviceMock",
		Status:                  "CERT_REVOKED",
		DmsId:                   1,
		Country:                 "ES",
		State:                   "Guipuzcoa",
		Locality:                "Mondragon",
		Organization:            "Ikerlan",
		OrganizationUnit:        "ZPD",
		CommonName:              "testDeviceMock",
		KeyType:                 "rsa",
		KeyBits:                 3072,
		CreationTimestamp:       "2022-01-11T07:02:40.082286Z",
		CurrentCertSerialNumber: "23-33-5b-19-c8-ed-8b-2a-92-5c-7b-57-fc-47-45-e7-12-03-91-23",
	}

	return device
}

func testDeviceLogs() devicesModel.DeviceLogs {
	var Logs devicesModel.DeviceLogs
	var logList []devicesModel.DeviceLog
	log := devicesModel.DeviceLog{
		Id:         "1",
		DeviceId:   "1",
		LogType:    "",
		LogMessage: "",
		Timestamp:  "",
	}
	logList = append(logList, log)
	Logs = devicesModel.DeviceLogs{Logs: logList}
	return Logs
}

func testGetDeviceCert() devicesModel.DeviceCert{
	log := devicesModel.DeviceCert{
		DeviceId: "1",
		SerialNumber: "",
		CAName: "",
		Status: "",
		CRT: "",
		Country: "",
		State: "",
		Locality: "",
		Org: "",
		OrgUnit: "",
		CommonName: "",
		ValidFrom: "",
		ValidTo: "",	
	}
	return log
}

func testGetDeviceCertHistory() devicesModel.DeviceCertsHistory {
	var Certs devicesModel.DeviceCertsHistory
	var certList []devicesModel.DeviceCertHistory
	cert := devicesModel.DeviceCertHistory{

		DeviceId: "1",
		SerialNumber: "",
		IssuerSerialNumber: "",
		IsuuerName: "",
		Status: "",
		CreationTimestamp: "",
	}
	certList = append(certList, cert)
	Certs = devicesModel.DeviceCertsHistory{DeviceCertHistory: certList}
	return Certs
}

func testDMSCertsHistory() devicesModel.DMSCertsHistory {
	var Certs devicesModel.DMSCertsHistory
	var certList []devicesModel.DMSCertHistory
	cert := devicesModel.DMSCertHistory{
		DmsId:       1,
		IssuedCerts: 1,
	}
	certList = append(certList, cert)
	Certs = devicesModel.DMSCertsHistory{DMSCertsHistory: certList}
	return Certs
}

func testDmsLastIssuedCert()devicesModel.DMSsLastIssued{
	var Certs devicesModel.DMSsLastIssued
	var certList []devicesModel.DMSLastIssued
	cert := devicesModel.DMSLastIssued{
		DmsId:       1,
		Timestamp: "",
		SerialNumber: "",
	}
	certList = append(certList, cert)
	Certs = devicesModel.DMSsLastIssued{DMSLastIssued: certList}
	return Certs
}

func setup(t *testing.T) (Service, context.Context) {
	t.Helper()

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	ctx := context.Background()
	ctx = context.WithValue(ctx, "LamassuLogger", logger)

	level.Info(logger).Log("msg", "Jaeger tracer started")

	vaultClient, err := mocksCA.NewVaultSecretsMock(t)
	if err != nil {
		t.Fatal("Unable to create Vault in-memory client")
	}

	configs.NewConfig("")
	devicesDb, err := mocks.NewDevicedDBMock(t)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Devices database. Will sleep for 5 seconds and exit the program")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Devices database")

	srv := NewDevicesService(devicesDb, vaultClient, logger)
	return srv, ctx
}
