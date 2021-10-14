package certmonitor

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"time"
)


type Host struct {
	Certificate *x509.Certificate
	DomainName  string
	tlsConfig *tls.Config
}

type CertMonitor struct {
	Hosts                 []Host
	AdditionalRootCAPaths *[]string
	RootCAs               *x509.CertPool
}

func NewCertMonitor(hostDomains []string, additionalRootCAPaths *[]string) (CertMonitor, error) {
	var err error

	cm := CertMonitor{
		Hosts:                 []Host{},
		AdditionalRootCAPaths: additionalRootCAPaths,
	}

	cm.getCertPool()
	if additionalRootCAPaths != nil {
		err = cm.addAdditionalRootCertsFromFile()

		if err != nil {
			return CertMonitor{}, err
		}
	}
	tlsConfig := getTLSConfig(cm.RootCAs)


	var hosts []Host
	for _, h := range hostDomains {

		hosts = append(hosts, Host{
			DomainName:  h,
			Certificate: &x509.Certificate{},
			tlsConfig:  tlsConfig,
		})
	}

	cm.Hosts = hosts
	return cm, nil

}

func (cm *CertMonitor) getCertPool() {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	cm.RootCAs = rootCAs
}

func (cm *CertMonitor) addAdditionalRootCertsFromFile() error {

	if cm.AdditionalRootCAPaths == nil {
		return nil
	}
	for _, file := range *cm.AdditionalRootCAPaths {
		certs, err := ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("Error reading additional cert file %s:   error: %s", file, err.Error())
		}
		cm.RootCAs.AppendCertsFromPEM(certs)
	}
	return nil
}



func getTLSConfig(ca *x509.CertPool) *tls.Config{
	return &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            ca,
	}

}
func (h *Host) SecondsUntilExpired() float64 {
	then := h.Certificate.NotAfter.UTC()
	now := time.Now().UTC()
	diff := then.Sub(now)
	return diff.Seconds()
}
func (h *Host) MinutesUntilExpired() float64 {
	then := h.Certificate.NotAfter.UTC()
	now := time.Now().UTC()
	diff := then.Sub(now)
	return diff.Minutes()
}
func (h *Host) HoursUntilExpired() float64 {
	then := h.Certificate.NotAfter.UTC()
	now := time.Now().UTC()
	diff := then.Sub(now)
	return diff.Hours()
}
func (h *Host) GetCertificate() error {

	conn, err := tls.Dial("tcp", fmt.Sprintf( "%s:%d", h.DomainName, 443), h.tlsConfig)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0{
		h.Certificate = state.PeerCertificates[0]
		h.SecondsUntilExpired()
		return nil
	}
	return fmt.Errorf("No certs returned")

}
