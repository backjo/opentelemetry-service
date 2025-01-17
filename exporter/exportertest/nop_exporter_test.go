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
package exportertest

import (
	"context"
	"errors"
	"testing"

	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/open-telemetry/opentelemetry-service/consumer/consumerdata"
)

func TestNopTraceExporter_NoErrors(t *testing.T) {
	nte := NewNopTraceExporter()
	td := consumerdata.TraceData{
		Spans: make([]*tracepb.Span, 7),
	}
	if err := nte.ConsumeTraceData(context.Background(), td); err != nil {
		t.Fatalf("Wanted nil got error")
	}
	if nte.Name() != "nop_trace" {
		t.Fatalf("Wanted nop_trace got %s", nte.Name())
	}
}

func TestNopTraceExporter_WithErrors(t *testing.T) {
	want := errors.New("MyError")
	nte := NewNopTraceExporter(WithReturnError(want))
	td := consumerdata.TraceData{
		Spans: make([]*tracepb.Span, 7),
	}
	if got := nte.ConsumeTraceData(context.Background(), td); got != want {
		t.Fatalf("Want %v Got %v", want, got)
	}
	if nte.Name() != "nop_trace" {
		t.Fatalf("Wanted nop_trace got %s", nte.Name())
	}
}

func TestNopMetricsExporter_NoErrors(t *testing.T) {
	nme := NewNopMetricsExporter()
	md := consumerdata.MetricsData{
		Metrics: make([]*metricspb.Metric, 7),
	}
	if err := nme.ConsumeMetricsData(context.Background(), md); err != nil {
		t.Fatalf("Wanted nil got error")
	}
	if nme.Name() != "nop_metrics" {
		t.Fatalf("Wanted nop_metrics got %s", nme.Name())
	}
}

func TestNopMetricsExporter_WithErrors(t *testing.T) {
	want := errors.New("MyError")
	nme := NewNopMetricsExporter(WithReturnError(want))
	md := consumerdata.MetricsData{
		Metrics: make([]*metricspb.Metric, 7),
	}
	if got := nme.ConsumeMetricsData(context.Background(), md); got != want {
		t.Fatalf("Want %v Got %v", want, got)
	}
	if nme.Name() != "nop_metrics" {
		t.Fatalf("Wanted nop_metrics got %s", nme.Name())
	}
}
