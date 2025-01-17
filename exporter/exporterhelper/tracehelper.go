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

package exporterhelper

import (
	"context"

	"go.opencensus.io/trace"

	"github.com/open-telemetry/opentelemetry-service/consumer/consumerdata"
	"github.com/open-telemetry/opentelemetry-service/exporter"
	"github.com/open-telemetry/opentelemetry-service/observability"
)

// PushTraceData is a helper function that is similar to ConsumeTraceData but also returns
// the number of dropped spans.
type PushTraceData func(ctx context.Context, td consumerdata.TraceData) (droppedSpans int, err error)

type traceExporter struct {
	exporterName  string
	pushTraceData PushTraceData
}

var _ (exporter.TraceExporter) = (*traceExporter)(nil)

func (te *traceExporter) ConsumeTraceData(ctx context.Context, td consumerdata.TraceData) error {
	exporterCtx := observability.ContextWithExporterName(ctx, te.exporterName)
	_, err := te.pushTraceData(exporterCtx, td)
	return err
}

func (te *traceExporter) Name() string {
	return te.exporterName
}

// NewTraceExporter creates an TraceExporter that can record metrics and can wrap every request with a Span.
// If no options are passed it just adds the exporter format as a tag in the Context.
// TODO: Add support for retries.
func NewTraceExporter(exporterName string, pushTraceData PushTraceData, options ...ExporterOption) (exporter.TraceExporter, error) {
	if exporterName == "" {
		return nil, errEmptyExporterName
	}

	if pushTraceData == nil {
		return nil, errNilPushTraceData
	}

	opts := newExporterOptions(options...)
	if opts.recordMetrics {
		pushTraceData = pushTraceDataWithMetrics(pushTraceData)
	}

	if opts.spanName != "" {
		pushTraceData = pushTraceDataWithSpan(pushTraceData, opts.spanName)
	}

	return &traceExporter{
		exporterName:  exporterName,
		pushTraceData: pushTraceData,
	}, nil
}

func pushTraceDataWithMetrics(next PushTraceData) PushTraceData {
	return func(ctx context.Context, td consumerdata.TraceData) (int, error) {
		// TODO: Add retry logic here if we want to support because we need to record special metrics.
		droppedSpans, err := next(ctx, td)
		// TODO: How to record the reason of dropping?
		observability.RecordTraceExporterMetrics(ctx, len(td.Spans), droppedSpans)
		return droppedSpans, err
	}
}

func pushTraceDataWithSpan(next PushTraceData, spanName string) PushTraceData {
	return func(ctx context.Context, td consumerdata.TraceData) (int, error) {
		ctx, span := trace.StartSpan(ctx, spanName)
		defer span.End()
		// Call next stage.
		droppedSpans, err := next(ctx, td)
		if span.IsRecordingEvents() {
			span.AddAttributes(
				trace.Int64Attribute(numReceivedSpansAttribute, int64(len(td.Spans))),
				trace.Int64Attribute(numDroppedSpansAttribute, int64(droppedSpans)),
			)
			if err != nil {
				span.SetStatus(errToStatus(err))
			}
		}
		return droppedSpans, err
	}
}
