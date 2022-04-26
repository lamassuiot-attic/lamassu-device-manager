package device

type Device struct {
	Id                    string                        `json:"id"`
	Alias                 string                        `json:"alias"`
	Description           string                        `json:"description"`
	Tags                  []string                      `json:"tags"`
	IconName              string                        `json:"icon_name"`
	IconColor             string                        `json:"icon_color"`
	Status                string                        `json:"status,omitempty"`
	DmsId                 string                        `json:"dms_id"`
	KeyMetadata           PrivateKeyMetadataWithStregth `json:"key_metadata,omitempty"`
	Subject               Subject                       `json:"subject,omitempty"`
	CreationTimestamp     string                        `json:"creation_timestamp,omitempty"`
	ModificationTimestamp string                        `json:"modification_timestamp,omitempty"`
	CurrentCertificate    CurrentCertificate            `json:"current_certificate,omitempty"`
}
type CurrentCertificate struct {
	SerialNumber string `json:"serial_number,omitempty"`
	Valid_to     string `json:"valid_to,omitempty"`
	Cert         string `json:"crt,omitempty"`
}
type PrivateKeyMetadata struct {
	KeyType string `json:"type"`
	KeyBits int    `json:"bits"`
}

type IconType struct {
	IconName  string `json:"icon_name"`
	IconColor string `json:"icon_color"`
}

type PrivateKeyMetadataWithStregth struct {
	KeyType     string `json:"type,omitempty"`
	KeyBits     int    `json:"bits,omitempty"`
	KeyStrength string `json:"strength,omitempty"`
}
type Subject struct {
	CN string `json:"common_name,omitempty"`
	O  string `json:"organization,omitempty"`
	OU string `json:"organization_unit,omitempty"`
	C  string `json:"country,omitempty"`
	ST string `json:"state,omitempty"`
	L  string `json:"locality,omitempty"`
}
type DeviceCertHistory struct {
	DeviceId            string `json:"device_id"`
	SerialNumber        string `json:"serial_number"`
	IsuuerName          string `json:"issuer_name"`
	Status              string `json:"status"`
	CreationTimestamp   string `json:"creation_timestamp"`
	RevocationTimestamp string `json:"revocation_timestamp"`
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
	DmsId       string `json:"dms_id"`
	IssuedCerts int    `json:"issued_certs"`
}
type DMSLastIssued struct {
	DmsId        string `json:"dms_id"`
	Timestamp    string `json:"timestamp"`
	SerialNumber string `json:"serial_number"`
}
type PaginationOptions struct {
	Page   int `json:"page"`
	Offset int `json:"offset"`
}
type OrderOptions struct {
	Order string `json:"order"`
	Field string `json:"field"`
}

type QueryParameters struct {
	Filter     string            `json:"filter"`
	Order      OrderOptions      `json:"order_options"`
	Pagination PaginationOptions `json:"pagination_options"`
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
