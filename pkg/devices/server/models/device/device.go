package device

type Device struct {
	Id                      string                        `json:"id"`
	Alias                   string                        `json:"alias"`
	Status                  string                        `json:"status,omitempty"`
	DmsId                   int                           `json:"dms_id"`
	KeyMetadata             PrivateKeyMetadataWithStregth `json:"key_metadata"`
	Subject                 Subject                       `json:"subject"`
	CreationTimestamp       string                        `json:"creation_timestamp,omitempty"`
	CurrentCertSerialNumber string                        `json:"current_cert_serial_number"`
}

type PrivateKeyMetadata struct {
	KeyType string `json:"type"`
	KeyBits int    `json:"bits"`
}
type PrivateKeyMetadataWithStregth struct {
	KeyType     string `json:"type"`
	KeyBits     int    `json:"bits"`
	KeyStrength string `json:"strength"`
}
type Subject struct {
	CN string `json:"common_name"`
	O  string `json:"organization"`
	OU string `json:"organization_unit"`
	C  string `json:"country"`
	ST string `json:"state"`
	L  string `json:"locality"`
}
type DeviceCertHistory struct {
	DeviceId           string `json:"device_id"`
	SerialNumber       string `json:"serial_number"`
	IssuerSerialNumber string `json:"issuer_serial_number"`
	IsuuerName         string `json:"issuer_name"`
	Status             string `json:"status"`
	CreationTimestamp  string `json:"creation_timestamp"`
}

type DeviceCert struct {
	DeviceId     string  `json:"device_id"`
	SerialNumber string  `json:"serial_number"`
	CAName       string  `json:"issuer_name"`
	Status       string  `json:"status"`
	CRT          string  `json:"crt"`
	Subject      Subject `json:"subject"`
	ValidFrom    string  `json:"valid_from"`
	ValidTo      string  `json:"valid_to"`
}

type DeviceLog struct {
	Id         string `json:"id"`
	DeviceId   string `json:"device_id"`
	LogType    string `json:"log_type"`
	LogMessage string `json:"log_message"`
	Timestamp  string `json:"timestamp"`
}
type DMSCertHistory struct {
	DmsId       int `json:"dms_id"`
	IssuedCerts int `json:"issued_certs"`
}
type DMSLastIssued struct {
	DmsId        int    `json:"dms_id"`
	Timestamp    string `json:"timestamp"`
	SerialNumber string `json:"serial_number"`
}

const ( // Device status
	DevicePendingProvision = "PENDING_PROVISION"
	DeviceProvisioned      = "DEVICE_PROVISIONED"
	DeviceCertRevoked      = "CERT_REVOKED"
	DeviceCertExpired      = "CERT_EXPIRED"
	DeviceDecommisioned    = "DEVICE_DECOMMISIONED"
)

const ( // Device Logs types
	LogDeviceCreated       = "LOG_DEVICE_CREATED"
	LogPendingProvision    = "LOG_PENDING_PROVISION"
	LogProvisioned         = "LOG_PROVISIONED"
	LogCertRevoked         = "LOG_CERT_REVOKED"
	LogCertExpired         = "LOG_CERT_EXPIRED"
	LogDeviceDecommisioned = "LOG_DEVICE_DECOMMISIONED"
)

const ( // Cert History status
	CertHistoryActive  = "ACTIVE"
	CertHistoryExpired = "EXPIRED"
	CertHistoryRevoked = "REVOKED"
)
