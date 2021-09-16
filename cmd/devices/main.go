package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"path"
	"time"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/ca"
	"github.com/lamassuiot/lamassu-est/server/estserver"

	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/api"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/auth"
	"github.com/go-openapi/runtime/middleware"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/configs"
	"github.com/lamassuiot/lamassu-device-manager/pkg/devices/discovery/consul"
	devicesDb "github.com/lamassuiot/lamassu-device-manager/pkg/devices/models/device/store/db"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
)

func main() {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	

	err, cfg := configs.NewConfig("devices")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	devicesConnStr := "dbname=" + cfg.PostgresDB + " user=" + cfg.PostgresUser + " password=" + cfg.PostgresPassword + " host=" + cfg.PostgresHostname + " port=" + cfg.PostgresPort + " sslmode=disable"
	devicesDb, err := devicesDb.NewDB("postgres", devicesConnStr, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Devices database. Will sleep for 5 seconds and exit the program")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Devices database")

	auth := auth.NewAuth(cfg.KeycloakHostname, cfg.KeycloakPort, cfg.KeycloakProtocol, cfg.KeycloakRealm, cfg.KeycloakCA)
	level.Info(logger).Log("msg", "Connection established with authentication system")

	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")
	tracer, closer, err := jcfg.NewTracer()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")

	fieldKeys := []string{"method", "error"}

	caPem, err := ioutil.ReadFile(cfg.CACertfile)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read CA cert file")
		os.Exit(1)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPem)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	caClient := &http.Client{Transport: tr}
	caUrl := cfg.CAServerAddr

	keycloakPem, err := ioutil.ReadFile(cfg.KeycloakCA)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read Keycloak cert file")
		os.Exit(1)
	}
	certPoolKeycloak := x509.NewCertPool()
	certPoolKeycloak.AppendCertsFromPEM(keycloakPem)

	trKeycloak := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPoolKeycloak,
		},
	}
	keycloakClient := &http.Client{Transport: trKeycloak}
	keycloakUrl := cfg.KeycloakProtocol + "://" + cfg.KeycloakHostname + ":" + cfg.KeycloakPort + "/auth/realms/" + cfg.KeycloakRealm
	var s api.Service
	{
		s = api.NewDevicesService(devicesDb, caClient, caUrl, keycloakClient, keycloakUrl, cfg.KeycloakClientId, cfg.KeycloakClientSecret)
		s = api.LoggingMiddleware(logger)(s)
		s = api.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "enroller",
				Subsystem: "enroller_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "enroller",
				Subsystem: "enroller_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(s)
	}

	consulsd, err := consul.NewServiceDiscovery(cfg.ConsulProtocol, cfg.ConsulHost, cfg.ConsulPort, cfg.ConsulCA, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Consul Service Discovery")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Consul Service Discovery")
	err = consulsd.Register("https", "device-manager", cfg.Port)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not register service liveness information to Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information registered to Consul")

	mux := http.NewServeMux()

	mux.Handle("/v1/", api.MakeHTTPHandler(s, log.With(logger, "component", "HTTPS"), auth, tracer))
	http.Handle("/v1/docs", middleware.SwaggerUI(middleware.SwaggerUIOpts{
		BasePath: "/v1/",
		SpecURL:  path.Join("/", "swagger.json"),
		Path:     "docs",
	}, mux))
	http.Handle("/", accessControl(mux, "", "", ""))
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/swagger.json", http.FileServer(http.Dir("./docs")))

	minimumReenrollDays, err := strconv.Atoi(cfg.MinimumReenrollDays)

	ca := ca.NewEstService(devicesDb, caClient, caUrl, keycloakClient, keycloakUrl, cfg.KeycloakClientId, cfg.KeycloakClientSecret, minimumReenrollDays, logger)
	server, _ := estserver.NewServerDeviceManager(ca)

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		level.Info(logger).Log("transport", "HTTPS", "address", ":"+cfg.Port, "msg", "listening")
		errs <- http.ListenAndServeTLS(":"+cfg.Port, cfg.CertFile, cfg.KeyFile, nil)
	}()

	go server.ListenAndServeTLS("", "")

	level.Info(logger).Log("exit", <-errs)
	err = consulsd.Deregister()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not deregister service liveness information from Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information deregistered from Consul")

}

func accessControl(h http.Handler, enrollerUIProtocol string, enrollerUIHost string, enrollerUIPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*var uiURL string
		if enrollerUIPort == "" {
			uiURL = enrollerUIProtocol + "://" + enrollerUIHost
		} else {
			uiURL = enrollerUIProtocol + "://" + enrollerUIHost + ":" + enrollerUIPort
		}*/
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
