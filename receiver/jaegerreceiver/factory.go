// Copyright 2019, OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jaegerreceiver

// This file implements factory for Jaeger receiver.

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-service/config/configerror"
	"github.com/open-telemetry/opentelemetry-service/config/configmodels"
	"github.com/open-telemetry/opentelemetry-service/consumer"
	"github.com/open-telemetry/opentelemetry-service/receiver"
)

const (
	// The value of "type" key in configuration.
	typeStr = "jaeger"

	// Protocol values.
	protoGRPC       = "grpc"
	protoThriftHTTP = "thrift-http"

	// Default endpoints to bind to.
	defaultGRPCBindEndpoint = "127.0.0.1:14250"
	defaultHTTPBindEndpoint = "127.0.0.1:14268"
)

// Factory is the factory for Jaeger receiver.
type Factory struct {
}

// Type gets the type of the Receiver config created by this factory.
func (f *Factory) Type() string {
	return typeStr
}

// CustomUnmarshaler returns nil because we don't need custom unmarshaling for this config.
func (f *Factory) CustomUnmarshaler() receiver.CustomUnmarshaler {
	return nil
}

// CreateDefaultConfig creates the default configuration for Jaeger receiver.
func (f *Factory) CreateDefaultConfig() configmodels.Receiver {
	return &Config{
		TypeVal: typeStr,
		NameVal: typeStr,
		Protocols: map[string]*configmodels.ReceiverSettings{
			protoGRPC: {
				Endpoint: defaultGRPCBindEndpoint,
			},
			protoThriftHTTP: {
				Endpoint: defaultHTTPBindEndpoint,
			},
		},
	}
}

// CreateTraceReceiver creates a trace receiver based on provided config.
func (f *Factory) CreateTraceReceiver(
	ctx context.Context,
	logger *zap.Logger,
	cfg configmodels.Receiver,
	nextConsumer consumer.TraceConsumer,
) (receiver.TraceReceiver, error) {

	// Convert settings in the source config to Configuration struct
	// that Jaeger receiver understands.

	rCfg := cfg.(*Config)

	protoGRPC := rCfg.Protocols[protoGRPC]
	protoHTTP := rCfg.Protocols[protoThriftHTTP]

	config := Configuration{}

	// Set ports
	if protoGRPC != nil && protoGRPC.IsEnabled() {
		var err error
		config.CollectorGRPCPort, err = extractPortFromEndpoint(protoGRPC.Endpoint)
		if err != nil {
			return nil, err
		}
	}

	if protoHTTP != nil && protoHTTP.IsEnabled() {
		var err error
		config.CollectorHTTPPort, err = extractPortFromEndpoint(protoHTTP.Endpoint)
		if err != nil {
			return nil, err
		}
	}

	if (protoGRPC == nil && protoHTTP == nil) ||
		(config.CollectorGRPCPort == 0 && config.CollectorHTTPPort == 0) {
		err := fmt.Errorf("either %v or %v protocol endpoint with non-zero port must be enabled for %s receiver",
			protoGRPC,
			protoThriftHTTP,
			typeStr,
		)
		return nil, err
	}

	// Create the receiver.
	return New(ctx, &config, nextConsumer)
}

// CreateMetricsReceiver creates a metrics receiver based on provided config.
func (f *Factory) CreateMetricsReceiver(
	logger *zap.Logger,
	cfg configmodels.Receiver,
	consumer consumer.MetricsConsumer,
) (receiver.MetricsReceiver, error) {
	return nil, configerror.ErrDataTypeIsNotSupported
}

// extract the port number from string in "address:port" format. If the
// port number cannot be extracted returns an error.
func extractPortFromEndpoint(endpoint string) (int, error) {
	_, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, fmt.Errorf("endpoint is not formatted correctly: %s", err.Error())
	}
	port, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		return 0, fmt.Errorf("endpoint port is not a number: %s", err.Error())
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port number must be between 1 and 65535")
	}
	return int(port), nil
}
