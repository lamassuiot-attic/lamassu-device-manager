package mtls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	stdhttp "net/http"
	"net/url"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/transport/http"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/configs"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/server/utils"
)

type contextKey string

const (
	PeerCertificatesContextKey contextKey = "PeerCertificatesContextKey"
	XForwardedCertifcate       contextKey = "XForwardedCertificate"
)

var (
	ErrPeerCertificatesContextMissing = errors.New("certificate up for parsing was not passed through the context")
)

func HTTPToContext() http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		ClientCert := r.Header.Get("x-forwarded-client-cert")
		if len(ClientCert) > 0 {
			splits := strings.Split(ClientCert, ";")
			Cert := splits[1]
			Cert = strings.Split(Cert, "=")[1]
			Cert = strings.Replace(Cert, "\"", "", -1)
			decodedCert, _ := url.QueryUnescape(Cert)
			block, _ := pem.Decode([]byte(decodedCert))
			certificate, _ := x509.ParseCertificate(block.Bytes)
			return context.WithValue(ctx, XForwardedCertifcate, certificate)
		} else if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certificate := r.TLS.PeerCertificates[0]
			return context.WithValue(ctx, PeerCertificatesContextKey, certificate)
		} else {
			return ctx
		}
	}
}
func NewParser(enroll bool, verify utils.Utils, cfg configs.Config, ctx context.Context) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			XForCert, _ := ctx.Value(XForwardedCertifcate).(*x509.Certificate)
			peerCert, _ := ctx.Value(PeerCertificatesContextKey).(*x509.Certificate)
			if XForCert != nil {
				_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peerCert.Raw})
				_, err = verify.VerifyPeerCertificate(ctx, peerCert, enroll, nil)
				if err != nil {
					return nil, err
				}
				return next(ctx, request)
			} else if peerCert != nil {
				certContent, err := ioutil.ReadFile(cfg.MutualTLSClientCA)
				if err != nil {
					return nil, err
				}
				cpb, _ := pem.Decode(certContent)
				crt, err := x509.ParseCertificate(cpb.Bytes)
				if err != nil {
					return nil, err
				}
				_, err = verify.VerifyPeerCertificate(ctx, peerCert, enroll, crt)
				if err != nil {
					return nil, err
				}
				return next(ctx, request)
			} else {
				return nil, ErrPeerCertificatesContextMissing
			}

		}
	}
}
