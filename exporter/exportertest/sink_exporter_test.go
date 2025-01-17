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
	"reflect"
	"testing"

	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/open-telemetry/opentelemetry-service/consumer/consumerdata"
)

func TestSinkTraceExporter(t *testing.T) {
	sink := new(SinkTraceExporter)
	td := consumerdata.TraceData{
		Spans: make([]*tracepb.Span, 7),
	}
	want := make([]consumerdata.TraceData, 0, 7)
	for i := 0; i < 7; i++ {
		if err := sink.ConsumeTraceData(context.Background(), td); err != nil {
			t.Fatalf("Wanted nil got error")
		}
		want = append(want, td)
	}
	got := sink.AllTraces()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Mismatches responses\nGot:\n\t%v\nWant:\n\t%v\n", got, want)
	}
	if sink.Name() != "sink_trace" {
		t.Errorf("Wanted sink_trace got %s", sink.Name())
	}
}

func TestSinkMetricsExporter(t *testing.T) {
	sink := new(SinkMetricsExporter)
	md := consumerdata.MetricsData{
		Metrics: make([]*metricspb.Metric, 7),
	}
	want := make([]consumerdata.MetricsData, 0, 7)
	for i := 0; i < 7; i++ {
		if err := sink.ConsumeMetricsData(context.Background(), md); err != nil {
			t.Fatalf("Wanted nil got error")
		}
		want = append(want, md)
	}
	got := sink.AllMetrics()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Mismatches responses\nGot:\n\t%v\nWant:\n\t%v\n", got, want)
	}
	if sink.Name() != "sink_metrics" {
		t.Errorf("Wanted sink_metrics got %s", sink.Name())
	}
}
