// Copyright 2019 OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/open-telemetry/opentelemetry-service/config/configmodels"
)

// SecureExporterSettings defines common settings for exporters that use gRPC
type SecureExporterSettings struct {
	configmodels.ExporterSettings `mapstructure:",squash"` // squash ensures fields are correctly decoded in embedded struct
	// Configures the exporter to use TLS.
	// The default value is nil, which will cause the receiver to not use TLS.
	TLSSettings TLSSettings `mapstructure:",squash"`
}

// TLSSettings contains path information for a certificate and key to be used for TLS
type TLSSettings struct {
	// CertFile is the file path containing the TLS certificate.
	CertPemFile string `mapstructure:"cert-pem-file"`

	// UseSecure specifies whether to use a secure channel for communication.
	UseSecure bool `mapstructure:"secure,omitempty"`

	// ServerNameOverride is the hostname to check against during certificate validation. If empty, will use the endpoint value.
	ServerNameOverride string `mapstructure:"server-name-override"`
}

// ToGrpcDialOption creates a gRPC DialOption from TLSSettings. If TLSSettings is nil, returns empty option.
func (tlsSettings *TLSSettings) ToGrpcDialOption() (opt grpc.DialOption, err error) {
	var transportCreds credentials.TransportCredentials;
	if tlsSettings == nil {
		return grpc.WithInsecure(), nil
	}
	if tlsSettings.CertPemFile != "" {
		transportCreds, err = credentials.NewClientTLSFromFile(tlsSettings.CertPemFile, tlsSettings.ServerNameOverride)
		if err != nil {
			return nil, err
		}
	} else if tlsSettings.UseSecure{
		certPool, _ := x509.SystemCertPool()
		config := &tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            certPool,
			ServerName: tlsSettings.ServerNameOverride,
		}
		transportCreds = credentials.NewTLS(config)
	} else {
		return grpc.WithInsecure(), nil
	}
	return grpc.WithTransportCredentials(transportCreds), nil
}
