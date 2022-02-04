package docs

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/configs"
)

func NewOpenAPI3(config configs.Config) openapi3.T {

	arrayOf := func(items *openapi3.SchemaRef) *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "array", Items: items}}
	}

	openapiSpec := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:       "Lamassu Device Manager API",
			Description: "REST API used for interacting with Lamassu Device Manager",
			Version:     "0.0.0",
			License: &openapi3.License{
				Name: "MPL v2.0",
				URL:  "https://github.com/lamassuiot/lamassu-compose/blob/main/LICENSE",
			},
			Contact: &openapi3.Contact{
				URL: "https://github.com/lamassuiot",
			},
		},
		Servers: openapi3.Servers{
			&openapi3.Server{
				Description: "Current Server",
				URL:         "/",
			},
		},
	}

	openapiSpec.Components.Schemas = openapi3.Schemas{

		"Device": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("id", openapi3.NewStringSchema()).
				WithProperty("alias", openapi3.NewStringSchema()).
				WithProperty("status", openapi3.NewStringSchema()).
				WithProperty("dms_id", openapi3.NewIntegerSchema()).
				WithProperty("country", openapi3.NewStringSchema()).
				WithProperty("state", openapi3.NewStringSchema()).
				WithProperty("locality", openapi3.NewStringSchema()).
				WithProperty("organization", openapi3.NewStringSchema()).
				WithProperty("organization_unit", openapi3.NewStringSchema()).
				WithProperty("common_name", openapi3.NewStringSchema()).
				WithProperty("key_type", openapi3.NewStringSchema()).
				WithProperty("key_bits", openapi3.NewIntegerSchema()).
				WithProperty("key_strength", openapi3.NewStringSchema()).
				WithProperty("creation_timestamp", openapi3.NewStringSchema()).
				WithProperty("current_cert_serial_number", openapi3.NewStringSchema()),
		),
		"DeviceCertHistory": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("device_id", openapi3.NewStringSchema()).
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithProperty("issuer_serial_number", openapi3.NewStringSchema()).
				WithProperty("issuer_name", openapi3.NewStringSchema()).
				WithProperty("status", openapi3.NewStringSchema()).
				WithProperty("creation_timestamp", openapi3.NewStringSchema()),
		),
		"DeviceCert": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("device_id", openapi3.NewStringSchema()).
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithProperty("issuer_name", openapi3.NewStringSchema()).
				WithProperty("status", openapi3.NewStringSchema()).
				WithProperty("crt", openapi3.NewStringSchema()).
				WithProperty("country", openapi3.NewStringSchema()).
				WithProperty("state", openapi3.NewStringSchema()).
				WithProperty("locality", openapi3.NewStringSchema()).
				WithProperty("organization", openapi3.NewStringSchema()).
				WithProperty("organization_unit", openapi3.NewStringSchema()).
				WithProperty("common_name", openapi3.NewStringSchema()).
				WithProperty("valid_from", openapi3.NewStringSchema()).
				WithProperty("valid_to", openapi3.NewStringSchema()),
		),
		"DeviceLog": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("id", openapi3.NewStringSchema()).
				WithProperty("device_id", openapi3.NewStringSchema()).
				WithProperty("log_type", openapi3.NewStringSchema()).
				WithProperty("log_message", openapi3.NewStringSchema()).
				WithProperty("timestamp", openapi3.NewStringSchema()),
		),
	}

	openapiSpec.Components.RequestBodies = openapi3.RequestBodies{
		"PostDeviceRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for creating a new Certificate Authority").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithPropertyRef("subject", &openapi3.SchemaRef{
						Ref: "#/components/schemas/Device",
					}),
				),
		},
	}

	openapiSpec.Components.Responses = openapi3.Responses{
		"ErrorResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response when errors happen.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("error", openapi3.NewStringSchema()))),
		},
		"HealthResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after healthchecking.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("healthy", openapi3.NewBoolSchema())),
				),
		},
		"DeviceResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/Device",
				})),
		},
		"GetDeviceResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(arrayOf(&openapi3.SchemaRef{
					Ref: "#/components/schemas/Device",
				}))),
		},
		"DeleteRevokeResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after revoking a device.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema())),
		},
		"GetDeviceLogsResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting logs of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(arrayOf(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DeviceLog",
				}))),
		},
		"GetDeviceCertResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting certificate of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DeviceCert",
				})),
		},
		"GetDeviceCertHistoryResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting certificate history of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DeviceCertHistory",
				})),
		},
		"GetDmsLastIssueCertResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting last iisued certificate of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DeviceCertHistory",
				})),
		},
	}

	openapiSpec.Paths = openapi3.Paths{
		"/v1/health": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "Health",
				Description: "Get health status",
				Responses: openapi3.Responses{
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/HealthResponse",
					},
				},
			},
		},
		"/v1/devices": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDevices",
				Description: "Get Devices",
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetDeviceResponse",
					},
				},
			},
			Post: &openapi3.Operation{
				OperationID: "PostDevice",
				Description: "Post Device",
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/PostDeviceRequest",
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/DeviceResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceById",
				Description: "Get Device By Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/DeviceResponse",
					},
				},
			},
			Delete: &openapi3.Operation{
				OperationID: "DeleteDevice",
				Description: "Delete Device By Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						//TODO:
						Ref: "#/components/responses/StringResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/revoke": &openapi3.PathItem{
			Delete: &openapi3.Operation{
				OperationID: "DeleteRevoke",
				Description: "Delete Revoke device by Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/DeleteRevokeResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/logs": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceLogs",
				Description: "Get Device Logs of deviceId",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetDeviceLogsResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/cert": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceCert",
				Description: "Get Device Cert of deviceId",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetDeviceCertResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/cert-history": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceCertHistory",
				Description: "Get Device Cert History of deviceId",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetDeviceCertHistoryResponse",
					},
				},
			},
		},
		"/v1/devices/dms-cert-history/thirty-days": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDmsCertHistoryThirtyDays",
				Description: "Get Dms Cert History of last Thirty Days",
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetDeviceCertHistoryResponse",
					},
				},
			},
		},
		"/v1/devices/dms-cert-history/last-issued": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDmsLastIssueCert",
				Description: "Get Dms Cert History of last Thirty Days",
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetDmsLastIssueCertResponse",
					},
				},
			},
		},
	}

	return openapiSpec
}
