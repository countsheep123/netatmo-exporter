package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	scan "github.com/mattn/go-scan"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

var (
	namespace = "netatmo"
)

var (
	listenAddr      = os.Getenv("LISTEN_ADDR")
	metricsEndpoint = os.Getenv("METRICS_ENDPOINT")
	refreshToken    = os.Getenv("NETATMO_REFRESH_TOKEN")
	clientID        = os.Getenv("NETATMO_CLIENT_ID")
	clientSecret    = os.Getenv("NETATMO_CLIENT_SECRET")
)

func init() {
	prometheus.MustRegister(version.NewCollector("netatmo_exporter"))
}

func main() {
	fmt.Println("Starting netatmo_exporter", version.Info())
	fmt.Println("Build context", version.BuildContext())

	if len(refreshToken) == 0 {
		log.Fatal("require env: NETATMO_REFRESH_TOKEN")
	}
	if len(clientID) == 0 {
		log.Fatal("require env: NETATMO_CLIENT_ID")
	}
	if len(clientSecret) == 0 {
		log.Fatal("require env: NETATMO_CLIENT_SECRET")
	}

	fmt.Printf("LISTEN_ADDR: %s\n", listenAddr)
	fmt.Printf("METRICS_ENDPOINT: %s\n", metricsEndpoint)

	collector := newCollector()
	prometheus.MustRegister(collector)

	sig := make(chan os.Signal, 1)
	signal.Notify(
		sig,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer signal.Stop(sig)

	mux := http.NewServeMux()
	mux.Handle(metricsEndpoint, promhttp.Handler())

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}

type Collector struct {
	up          prometheus.Gauge
	temperature *prometheus.Desc
	humidity    *prometheus.Desc
	co2         *prometheus.Desc
	noise       *prometheus.Desc
	pressure    *prometheus.Desc
}

func newCollector() *Collector {
	return &Collector{
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "up",
		}),
		temperature: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "temperature"),
			"temperature",
			[]string{"device"},
			nil,
		),
		humidity: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "humidity"),
			"humidity",
			[]string{"device"},
			nil,
		),
		co2: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "co2"),
			"co2",
			[]string{"device"},
			nil,
		),
		noise: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "noise"),
			"noise",
			[]string{"device"},
			nil,
		),
		pressure: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "pressure"),
			"pressure",
			[]string{"device"},
			nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.up.Describe(ch)
	ch <- c.temperature
	ch <- c.humidity
	ch <- c.co2
	ch <- c.noise
	ch <- c.pressure
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	metrics, err := getData()
	if err != nil {
		log.Println(err)
		c.up.Set(0)
		ch <- c.up
		return
	}

	c.up.Set(1)
	ch <- c.up

	ch <- prometheus.MustNewConstMetric(
		c.temperature,
		prometheus.GaugeValue,
		metrics.temperature,
		fmt.Sprintf("%s-%s", metrics.stationName, metrics.moduleName),
	)
	ch <- prometheus.MustNewConstMetric(
		c.humidity,
		prometheus.GaugeValue,
		float64(metrics.humidity),
		fmt.Sprintf("%s-%s", metrics.stationName, metrics.moduleName),
	)
	ch <- prometheus.MustNewConstMetric(
		c.co2,
		prometheus.GaugeValue,
		float64(metrics.co2),
		fmt.Sprintf("%s-%s", metrics.stationName, metrics.moduleName),
	)
	ch <- prometheus.MustNewConstMetric(
		c.noise,
		prometheus.GaugeValue,
		float64(metrics.noise),
		fmt.Sprintf("%s-%s", metrics.stationName, metrics.moduleName),
	)
	ch <- prometheus.MustNewConstMetric(
		c.pressure,
		prometheus.GaugeValue,
		metrics.pressure,
		fmt.Sprintf("%s-%s", metrics.stationName, metrics.moduleName),
	)
}

type metrics struct {
	temperature float64
	humidity    int64
	co2         int64
	noise       int64
	pressure    float64

	stationName string
	moduleName  string
}

func getData() (*metrics, error) {
	accessToken, err := getAccessToken(refreshToken, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	metrics, err := getMetrics(accessToken)
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

func getAccessToken(refreshToken, clientID, clientSecret string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequest(http.MethodPost, "https://api.netatmo.com/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	header := http.Header{}
	header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header = header

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not get token")
	}

	var body map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}

	var accessToken string

	if err := scan.ScanTree(body, "/access_token", &accessToken); err != nil {
		return "", err
	}

	return accessToken, nil
}

func getMetrics(accessToken string) (*metrics, error) {
	u, err := url.Parse("https://api.netatmo.com/api/getstationsdata")
	if err != nil {
		return nil, err
	}

	queries := url.Values{}
	queries.Add("access_token", accessToken)
	u.RawQuery = queries.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid request")
	}

	var body map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}

	metrics := &metrics{}

	if err := scan.ScanTree(body, "/body/devices[0]/dashboard_data/Temperature", &metrics.temperature); err != nil {
		return nil, err
	}
	if err := scan.ScanTree(body, "/body/devices[0]/dashboard_data/Humidity", &metrics.humidity); err != nil {
		return nil, err
	}
	if err := scan.ScanTree(body, "/body/devices[0]/dashboard_data/CO2", &metrics.co2); err != nil {
		return nil, err
	}
	if err := scan.ScanTree(body, "/body/devices[0]/dashboard_data/Noise", &metrics.noise); err != nil {
		return nil, err
	}
	if err := scan.ScanTree(body, "/body/devices[0]/dashboard_data/Pressure", &metrics.pressure); err != nil {
		return nil, err
	}
	if err := scan.ScanTree(body, "/body/devices[0]/station_name", &metrics.stationName); err != nil {
		return nil, err
	}
	if err := scan.ScanTree(body, "/body/devices[0]/module_name", &metrics.moduleName); err != nil {
		return nil, err
	}

	return metrics, nil
}
