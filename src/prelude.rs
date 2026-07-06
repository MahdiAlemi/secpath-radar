//! Crate-wide prelude: external imports and re-exports of all modules.

pub(crate) use anyhow::{Context, Result};
pub(crate) use chrono::{
    Datelike, Duration as ChronoDuration, Local, NaiveDate, SecondsFormat, Utc,
};
pub(crate) use feed_rs::parser;
pub(crate) use minijinja::{context, Environment};
pub(crate) use reqwest::blocking::Client;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde_json::{json, Value};
pub(crate) use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    env, fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    thread,
    time::{Duration, SystemTime},
};

#[allow(unused_imports)]
pub(crate) use crate::{
    ai::*, brief::*, cache::*, cli::*, config::*, cve::*, history::*, intel::attack_pressure::*,
    intel::botnet_c2::*, intel::csaf::*, intel::greynoise::*, intel::ics_ot::*,
    intel::infrastructure::*, intel::ioc_radar::*, intel::malware_bazaar::*,
    intel::nuclei_coverage::*, intel::phishing::*, intel::poc_watch::*, intel::ransomware::*,
    intel::spamhaus_drop::*, intel::supply_chain::*, intel::*, model::*, news::*, output::*,
    polish::*, render::*, snapshot::*, trend::*, util::*, writeups::*,
};
