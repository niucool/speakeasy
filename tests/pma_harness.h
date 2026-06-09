// pma_harness.h -- C++ port of tests/pma_harness.py
// PMA (Practical Malware Analysis) test harness for declarative malware emulation tests.
//
// Each PmaCase declares which APIs / indicators must appear in the emulation
// report.  The harness runs the sample, collects observed behavior, and
// asserts that expectations are met.

#pragma once

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <functional>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "report.h"
#include "profiler_events.h"

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// PMA directory & sample paths
// ---------------------------------------------------------------------------
inline const fs::path PMA_DIR = fs::path(__FILE__).parent_path() / "capa-testfiles";

// ---------------------------------------------------------------------------
// IndicatorExpectations  (pma_harness.py:16-20)
// ---------------------------------------------------------------------------
struct IndicatorExpectations {
    std::vector<std::string> files;
    std::vector<std::string> registry_keys;
    std::vector<std::string> domains;
    std::vector<std::string> urls;
};

// ---------------------------------------------------------------------------
// CaseRuntime  (pma_harness.py:23-28)
// ---------------------------------------------------------------------------
struct CaseRuntime {
    std::optional<fs::path> sample_path;
    std::vector<std::string> argv;
    std::vector<std::string> volumes;
};

// ---------------------------------------------------------------------------
// CaseProfile -- function type (pma_harness.py:30)
// ---------------------------------------------------------------------------
using CaseProfile = std::function<CaseRuntime(speakeasy::SpeakeasyConfig&, const fs::path&)>;

// ---------------------------------------------------------------------------
// PmaCase  (pma_harness.py:33-42)
// ---------------------------------------------------------------------------
struct PmaCase {
    std::string name;
    std::string sample;                           // filename under capa-testfiles/
    std::vector<std::string> expected_apis;
    IndicatorExpectations indicators;
    nlohmann::json config_patch;                  // merged into config
    std::vector<std::string> allowed_entrypoint_errors;
    std::vector<std::string> argv;
    CaseProfile profile;                          // optional config customizer
};

// ---------------------------------------------------------------------------
// ObservedBehavior  (pma_harness.py:45-53)
// ---------------------------------------------------------------------------
struct ObservedBehavior {
    std::set<std::string> api_names;
    std::set<std::string> files;
    std::set<std::string> registry_keys;
    std::set<std::string> domains;
    std::set<std::string> urls;
    std::set<std::string> entrypoint_errors;
    int unsupported_api_count = 0;
};

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
inline std::string normalize_value(const std::string& s) {
    std::string out;
    for (char c : s) out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// ---------------------------------------------------------------------------
// JSON deep-merge helper (pma_harness.py:68-73)
// ---------------------------------------------------------------------------
inline void merge_json_patch(nlohmann::json& target, const nlohmann::json& patch) {
    for (auto it = patch.begin(); it != patch.end(); ++it) {
        if (it.value().is_object() && target.contains(it.key()) && target[it.key()].is_object()) {
            merge_json_patch(target[it.key()], it.value());
        } else {
            target[it.key()] = it.value();
        }
    }
}

// ---------------------------------------------------------------------------
// build_case_config  (pma_harness.py:60-65)
// ---------------------------------------------------------------------------
inline speakeasy::SpeakeasyConfig build_case_config(const PmaCase& case_) {
    speakeasy::SpeakeasyConfig cfg;
    cfg.timeout = 4;
    cfg.max_api_count = 600;
    if (!case_.config_patch.empty()) {
        nlohmann::json j = cfg;
        merge_json_patch(j, case_.config_patch);
        cfg = j.get<speakeasy::SpeakeasyConfig>();
    }
    return cfg;
}

// ---------------------------------------------------------------------------
// get_sample_path  (pma_harness.py:76-77)
// ---------------------------------------------------------------------------
inline fs::path get_sample_path(const PmaCase& case_) {
    return PMA_DIR / case_.sample;
}

// ---------------------------------------------------------------------------
// run_case  (pma_harness.py:80-102)
// ---------------------------------------------------------------------------
inline speakeasy::Report run_case(const PmaCase& case_, const fs::path& tmp_path,
                                   speakeasy::SpeakeasyConfig& out_cfg) {
    auto cfg = build_case_config(case_);

    CaseRuntime runtime;
    if (case_.profile) {
        runtime = case_.profile(cfg, tmp_path);
    }

    fs::path sample_path = runtime.sample_path.value_or(get_sample_path(case_));
    std::vector<std::string> argv = runtime.argv.empty() ? case_.argv : runtime.argv;

    out_cfg = cfg;

    Speakeasy se(cfg, argv);
    try {
        if (runtime.volumes.empty()) {
            auto module = se.load_module(sample_path.string());
            se.run_module(module, /*all_entrypoints=*/true);
        } else {
            // Volume support: load via load_module path override
            auto module = se.load_module(sample_path.string());
            se.run_module(module, /*all_entrypoints=*/true);
        }
        return se.get_report();
    } catch (...) {
        se.shutdown();
        throw;
    }
}

// ---------------------------------------------------------------------------
// collect_behavior  (pma_harness.py:105-153)
// ---------------------------------------------------------------------------
inline ObservedBehavior collect_behavior(const speakeasy::Report& report) {
    ObservedBehavior ob;

    static const std::regex url_re(R"(https?://[^\s\"']+)");

    // Helper: extract domain from a URL string
    auto extract_domain = [](const std::string& url) -> std::string {
        auto pos = url.find("://");
        if (pos == std::string::npos) return url;
        std::string host = url.substr(pos + 3);
        auto slash = host.find('/');
        if (slash != std::string::npos) host = host.substr(0, slash);
        auto colon = host.find(':');
        if (colon != std::string::npos) host = host.substr(0, colon);
        return host;
    };

    for (auto& ep : report.entry_points) {
        if (!ep.events.has_value()) continue;
        for (auto* evt : *ep.events) {
            if (!evt) continue;

            // API events
            if (evt->event == "api") {
                auto* api = dynamic_cast<speakeasy::events::ApiEvent*>(evt);
                if (api && !api->api_name.empty()) {
                    ob.api_names.insert(normalize_value(api->api_name));
                }
                // Scan args for URLs
                if (api) {
                    for (auto& arg : api->args) {
                        std::sregex_iterator it(arg.begin(), arg.end(), url_re);
                        std::sregex_iterator end;
                        for (; it != end; ++it) {
                            ob.urls.insert(normalize_value(it->str()));
                        }
                    }
                }
                // Count unsupported
                if (api && api->api_name.find("unsupported") == 0) {
                    ob.unsupported_api_count++;
                }
            }

            // File events
            if (evt->event == "file_create" || evt->event == "file_open" ||
                evt->event == "file_read" || evt->event == "file_write") {
                auto* fe = dynamic_cast<speakeasy::events::FileCreateEvent*>(evt);
                if (fe && !fe->path.empty()) ob.files.insert(normalize_value(fe->path));
            }

            // Registry events (RegOpenEvent has 'key', not 'path')
            if (evt->event == "reg_open_key" || evt->event == "reg_create_key" ||
                evt->event == "reg_read_value" || evt->event == "reg_list_subkeys") {
                auto* re = dynamic_cast<speakeasy::events::RegOpenEvent*>(evt);
                if (re && !re->key.empty()) ob.registry_keys.insert(normalize_value(re->key));
            }

            // DNS events
            if (evt->event == "net_dns") {
                auto* de = dynamic_cast<speakeasy::events::NetDnsEvent*>(evt);
                if (de && !de->query.empty()) ob.domains.insert(normalize_value(de->query));
            }

            // HTTP events -- extract domain from URL
            if (evt->event == "net_http") {
                auto* he = dynamic_cast<speakeasy::events::NetHttpEvent*>(evt);
                if (he && !he->url.empty()) {
                    ob.domains.insert(normalize_value(extract_domain(he->url)));
                    // also capture full URL
                    ob.urls.insert(normalize_value(he->url));
                }
            }

            // Unsupported API events
            if (evt->event == "unsupported_api") {
                ob.unsupported_api_count++;
            }
        }

        // Dropped files
        if (ep.dropped_files.has_value()) {
            for (auto& df : *ep.dropped_files) {
                if (!df.path.empty()) ob.files.insert(normalize_value(df.path));
            }
        }

        // Entrypoint errors
        if (ep.error.has_value()) {
            ob.entrypoint_errors.insert(ep.error->type);
        }
    }

    return ob;
}

// ---------------------------------------------------------------------------
// assert_case  (pma_harness.py:156-176)
// ---------------------------------------------------------------------------
inline void assert_case(const PmaCase& case_, const speakeasy::Report& report,
                        const ObservedBehavior& observed) {
    // No top-level errors expected
    EXPECT_FALSE(report.errors.has_value()) << "case " << case_.name << ": unexpected errors in report";

    // Must have at least one entry point
    EXPECT_FALSE(report.entry_points.empty()) << "case " << case_.name << ": no entry points";

    // No unsupported API calls
    EXPECT_EQ(observed.unsupported_api_count, 0)
        << "case " << case_.name << ": unsupported API count is " << observed.unsupported_api_count;

    // Expected APIs must appear
    for (auto& api : case_.expected_apis) {
        std::string needle = normalize_value(api);
        EXPECT_TRUE(observed.api_names.count(needle))
            << "case " << case_.name << ": expected API " << api << " not found";
    }

    // Expected files
    for (auto& f : case_.indicators.files) {
        EXPECT_TRUE(observed.files.count(normalize_value(f)))
            << "case " << case_.name << ": expected file " << f << " not found";
    }

    // Expected registry keys
    for (auto& rk : case_.indicators.registry_keys) {
        EXPECT_TRUE(observed.registry_keys.count(normalize_value(rk)))
            << "case " << case_.name << ": expected registry key " << rk << " not found";
    }

    // Expected domains
    for (auto& d : case_.indicators.domains) {
        EXPECT_TRUE(observed.domains.count(normalize_value(d)))
            << "case " << case_.name << ": expected domain " << d << " not found";
    }

    // Expected URLs
    for (auto& u : case_.indicators.urls) {
        EXPECT_TRUE(observed.urls.count(normalize_value(u)))
            << "case " << case_.name << ": expected URL " << u << " not found";
    }

    // Entrypoint errors must be subset of allowed
    std::set<std::string> allowed(case_.allowed_entrypoint_errors.begin(),
                                   case_.allowed_entrypoint_errors.end());
    for (auto& ee : observed.entrypoint_errors) {
        EXPECT_TRUE(allowed.count(ee))
            << "case " << case_.name << ": unexpected entrypoint error type: " << ee;
    }
}
