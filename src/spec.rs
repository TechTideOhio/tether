use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteConfig {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default = "default_held_out_ratio")]
    pub held_out_ratio: f64,
}

fn default_held_out_ratio() -> f64 {
    0.20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopConfig {
    #[serde(default = "default_min_new_cases")]
    pub min_new_cases_per_release: usize,
    #[serde(default = "default_max_unlabeled")]
    pub max_unlabeled_candidates: usize,
    #[serde(default = "default_true")]
    pub require_reproduction_before_close: bool,
}

fn default_min_new_cases() -> usize {
    3
}

fn default_max_unlabeled() -> usize {
    10
}

fn default_true() -> bool {
    true
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            min_new_cases_per_release: default_min_new_cases(),
            max_unlabeled_candidates: default_max_unlabeled(),
            require_reproduction_before_close: default_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    #[serde(default = "default_min_pass")]
    pub min_overall_pass_rate: f64,
    #[serde(default = "default_min_held_out")]
    pub min_held_out_pass_rate: f64,
    #[serde(default = "default_max_drop")]
    pub max_drop: f64,
    #[serde(default = "default_alpha")]
    pub mcnemar_alpha: f64,
    #[serde(default = "default_true")]
    pub require_held_out_win_or_tie: bool,
}

fn default_min_pass() -> f64 {
    0.88
}

fn default_min_held_out() -> f64 {
    0.85
}

fn default_max_drop() -> f64 {
    0.02
}

fn default_alpha() -> f64 {
    0.05
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_overall_pass_rate: default_min_pass(),
            min_held_out_pass_rate: default_min_held_out(),
            max_drop: default_max_drop(),
            mcnemar_alpha: default_alpha(),
            require_held_out_win_or_tie: default_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySpec {
    pub baseline_pass_rate: Option<f64>,
    pub floor_pass_rate: f64,
    #[serde(default = "default_max_drop")]
    pub max_drop: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetherSpec {
    pub suite: SuiteConfig,
    #[serde(rename = "loop", default)]
    pub loop_policy: LoopConfig,
    #[serde(default)]
    pub gate: GateConfig,
    #[serde(default)]
    pub category: HashMap<String, CategorySpec>,
}
