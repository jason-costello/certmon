package certmonitor

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"testing"
)
func readDomainNamesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return []string{}, fmt.Errorf("Failed to read file: %s", err.Error())
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil

}


func createCertMonitor() (CertMonitor, error){
	domainsFromFile, err := readDomainNamesFromFile("./test_data/domains.txt")
	if err != nil{
		return CertMonitor{}, nil
	}
	cm, err := NewCertMonitor(domainsFromFile, nil)
	if err != nil {
		return CertMonitor{}, nil
	}
	return cm, nil


}

func TestNewCertMonitor(t *testing.T) {

	domainsFromFile, err := readDomainNamesFromFile("./test_data/domains.txt")
	if err != nil{
		t.Fatal("Unable to get domains from txt file")
	}



	type args struct {
		hostDomains           []string
		additionalRootCAPaths *[]string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Valid Request",
			args: args{
				hostDomains:domainsFromFile,
				additionalRootCAPaths: &[]string{},
			},
			want: []string{"intelligence.rackspace.com",
				"monitoring.rackspace.net",
				"monitoring.api.rackspacecloud.com",
				"us.monitoring.api.rackspacecloud.com",
				"mnrva-deploy.dev.monplat.rackspace.net"},
			wantErr: false,
		},


	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertMonitor(tt.args.hostDomains, tt.args.additionalRootCAPaths)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertMonitor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var hosts []string
			for _, host := range got.Hosts{
				hosts = append(hosts, host.DomainName)
			}
			if !reflect.DeepEqual(hosts, tt.want) {
				t.Errorf("NewCertMonitor() got = %v, want %v", hosts, tt.want)
			}
		})
	}
}

func TestCertMonitor_getCertPool(t *testing.T) {

	cm, err :=createCertMonitor()
	if err != nil{
		t.Fatal(err.Error())

	}

	tests := []struct {
		name   string
		cm CertMonitor
		want *x509.CertPool
	}{
		{
			name: "Valid System Cert Pool",
			cm: cm,
		},

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm.getCertPool()
			got := tt.cm.RootCAs
			if got == nil{

				t.Errorf("NewCertMonitor() got = %v, want %v", "cert", tt.want)
			}

		})
	}
}

func TestHost_GetCertificate(t *testing.T) {
	rootCAs, _ := x509.SystemCertPool()
	type fields struct {
		Certificate *x509.Certificate
		DomainName  string
		tlsConfig   *tls.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want string
		wantErr bool
	}{
		{
			name: "Valid Google CN",
			fields: fields{
				Certificate: nil,
				DomainName:  "google.com",
				tlsConfig:   &tls.Config{
					InsecureSkipVerify: true,
					RootCAs:            rootCAs,
				},
			},
			want: "CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US",
			wantErr: false,
			
			},
		{
			name: "Valid mnrva-deploy.dev.monplat.rackspace.net CN",
			fields: fields{
				Certificate: nil,
				DomainName:  "mnrva-deploy.dev.monplat.rackspace.net",
				tlsConfig:   &tls.Config{
					InsecureSkipVerify: true,
					RootCAs:            rootCAs,
				},
			},
			want: `CN=*.dev.monplat.rackspace.net,OU=Monitoring,O=Rackspace US\, Inc.,L=San Antonio,ST=Texas,C=US`,
			wantErr: false,

		},

		{
			name: "Valid intelligence CN",
			fields: fields{
				Certificate: nil,
				DomainName:  "intelligence.rackspace.com",
				tlsConfig:   &tls.Config{
					InsecureSkipVerify: true,
					RootCAs:            rootCAs,
				},
			},
			want: "CN=intelligence.rackspace.com",
			wantErr: false,

		},
		{
			name: "Valid us.monitoring.api.rackspacecloud.com CN",
			fields: fields{
				Certificate: nil,
				DomainName:  "us.monitoring.api.rackspacecloud.com",
				tlsConfig:   &tls.Config{
					InsecureSkipVerify: true,
					RootCAs:            rootCAs,
				},
			},
			want: `SERIALNUMBER=4377687,CN=monitoring.api.rackspacecloud.com,O=Rackspace US\, Inc,L=San Antonio,ST=Texas,C=US`,
			wantErr: false,

		},
		{
			name: "Valid monitoring.api.rackspacecloud.com CN",
			fields: fields{
				Certificate: nil,
				DomainName:  "monitoring.api.rackspacecloud.com",
				tlsConfig:   &tls.Config{
					InsecureSkipVerify: true,
					RootCAs:            rootCAs,
				},
			},
			want: `SERIALNUMBER=4377687,CN=monitoring.api.rackspacecloud.com,O=Rackspace US\, Inc,L=San Antonio,ST=Texas,C=US`,
			wantErr: false,

		},
		{
			name: "Valid monitoring.rackspace.net CN",
			fields: fields{
				Certificate: nil,
				DomainName:  "monitoring.rackspace.net",
				tlsConfig:   &tls.Config{
					InsecureSkipVerify: true,
					RootCAs:            rootCAs,
				},
			},
			want: `CN=monitoring.rackspace.net,O=Rackspace US\, Inc.,L=San Antonio,ST=Texas,C=US`,
			wantErr: false,

		},


	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Host{
				Certificate: tt.fields.Certificate,
				DomainName:  tt.fields.DomainName,
				tlsConfig:   tt.fields.tlsConfig,
			}
			 err := h.GetCertificate()
			 if err != nil && !tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			 if err != nil && tt.wantErr{
			 	return
			 }

			sub := fmt.Sprintf("%v", h.Certificate.Subject)
			if !reflect.DeepEqual(sub, tt.want){
					t.Errorf("Hostname:   got:  %s      want:   %s", sub, tt.want)
					return
			}
		t.Logf("got: %s    want: %s", sub, tt.want)
		})
	}
}
