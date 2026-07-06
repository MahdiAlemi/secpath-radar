//! Passive intelligence pulses (observation-only).

use crate::prelude::*;

pub(crate) mod attack_pressure;
pub(crate) mod botnet_c2;
pub(crate) mod greynoise;
pub(crate) mod ics_ot;
pub(crate) mod infrastructure;
pub(crate) mod ioc_radar;
pub(crate) mod nuclei_coverage;
pub(crate) mod phishing;
pub(crate) mod poc_watch;
pub(crate) mod ransomware;
pub(crate) mod supply_chain;

pub(crate) fn intel_source_count(config: &Config) -> usize {
    if !config.intel.enabled {
        return 0;
    }

    let mut count = 0;
    if config.intel.attack_pressure.enabled {
        count += 1;
    }
    if config.intel.ioc_radar.enabled {
        count += 2;
    }
    if config.intel.infrastructure.enabled {
        count += 1;
    }
    if config.intel.supply_chain.enabled {
        count += 2;
    }
    if config.intel.ransomware.enabled {
        count += 1;
    }
    if config.intel.botnet_c2.enabled {
        count += 2;
    }
    if config.intel.greynoise.enabled {
        count += 1;
    }
    if config.intel.phishing.enabled {
        count += 1;
    }
    if config.intel.ics_ot.enabled {
        count += 1;
    }
    if config.intel.nuclei_coverage.enabled {
        count += 1;
    }
    if config.intel.poc_watch.enabled {
        count += 1;
    }
    count
}
