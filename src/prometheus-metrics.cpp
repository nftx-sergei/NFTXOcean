#include "prometheus-metrics.h"
#include "util.h"

#include <memory>
#include <utility>

// as we still tied to C++11 standart we should implement make_unique here
namespace std {
    template<typename T, typename ...Args>
    unique_ptr<T> make_unique(Args&& ... args) {
        return unique_ptr<T>(new T(std::forward<Args>(args)...));
    }
}

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

using namespace prometheus;

static bool fMetricInitialized = false;
bool IsMetricsInitialized() {
    return fMetricInitialized;
}

static class CPrometheusMetrics {
private:
    std::unique_ptr<Exposer> my_exposer;
    std::shared_ptr<Registry> my_registry;
    prometheus::Family<prometheus::Counter> &ref_read_solutions_counter;
    prometheus::Counter &counter_komodod_debug_blocktree_write_batch_read_dbindex;
    prometheus::Counter &counter_komodod_debug_blocktree_trimmed_equihash_read_dbindex;

    std::map<std::string, prometheus::Counter &> countersMap;

    public:
    CPrometheusMetrics() : my_exposer(new Exposer("127.0.0.1:9191")),
                           my_registry(std::make_shared<Registry>()),
                           // add a new counter family to the registry (families combine values with the same name, but distinct label dimensions)
                           ref_read_solutions_counter(BuildCounter().Name("solutions_read_total").Help("Number of read solutions").Register(*my_registry)),
                            // add and remember dimensional data
                           counter_komodod_debug_blocktree_write_batch_read_dbindex(ref_read_solutions_counter.Add({{"name", "komodod.debug.blocktree.write_batch_read_dbindex"}})),
                           counter_komodod_debug_blocktree_trimmed_equihash_read_dbindex(ref_read_solutions_counter.Add({{"name", "komodod.debug.blocktree.trimmed_equihash_read_dbindex"}}))
    {
        countersMap.insert({"komodod.debug.blocktree.write_batch_read_dbindex", counter_komodod_debug_blocktree_write_batch_read_dbindex});
        countersMap.insert({"komodod.debug.blocktree.trimmed_equihash_read_dbindex", counter_komodod_debug_blocktree_trimmed_equihash_read_dbindex});

        my_exposer->RegisterCollectable(my_registry);
        fMetricInitialized = true;
    }
    ~CPrometheusMetrics() {}
    void MetricsIncrementCounter(const std::string& method_name);
} instance_of_cprometheus_metrics;

void CPrometheusMetrics::MetricsIncrementCounter(const std::string &method_name)
{
    auto counter_it = countersMap.find(method_name);
    if (counter_it != countersMap.end()) {
        counter_it->second.Increment();
    }
}

void MetricsIncrementCounter(const std::string &method_name) {
    instance_of_cprometheus_metrics.MetricsIncrementCounter(method_name);
}