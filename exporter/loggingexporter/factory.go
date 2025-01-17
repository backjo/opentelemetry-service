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

package loggingexporter

import (
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-service/config/configmodels"
	"github.com/open-telemetry/opentelemetry-service/consumer"
	"github.com/open-telemetry/opentelemetry-service/exporter"
)

const (
	// The value of "type" key in configuration.
	typeStr = "logging"
)

// Factory is the factory for logging exporter.
type Factory struct {
}

// Type gets the type of the Exporter config created by this factory.
func (f *Factory) Type() string {
	return typeStr
}

// CreateDefaultConfig creates the default configuration for exporter.
func (f *Factory) CreateDefaultConfig() configmodels.Exporter {
	return &Config{
		ExporterSettings: configmodels.ExporterSettings{
			TypeVal: typeStr,
			NameVal: typeStr,
		},
	}
}

func noopStopFunc() error {
	return nil
}

// CreateTraceExporter creates a trace exporter based on this config.
func (f *Factory) CreateTraceExporter(logger *zap.Logger, cfg configmodels.Exporter) (consumer.TraceConsumer, exporter.StopFunc, error) {

	lexp, err := NewTraceExporter(cfg.Name(), logger)
	if err != nil {
		return nil, nil, err
	}
	return lexp, noopStopFunc, nil
}

// CreateMetricsExporter creates a metrics exporter based on this config.
func (f *Factory) CreateMetricsExporter(logger *zap.Logger, cfg configmodels.Exporter) (consumer.MetricsConsumer, exporter.StopFunc, error) {
	lexp, err := NewMetricsExporter(cfg.Name(), logger)
	if err != nil {
		return nil, nil, err
	}
	return lexp, noopStopFunc, nil
}
