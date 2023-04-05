#ifndef PROMETHEUS_METRICS_H
#define PROMETHEUS_METRICS_H

#include <string>

bool IsMetricsInitialized();
void MetricsIncrementCounter(const std::string &method_name);

#endif // PROMETHEUS_METRICS_H

