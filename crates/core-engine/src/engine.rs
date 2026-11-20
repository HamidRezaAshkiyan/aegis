use crate::config::{AegisConfig, BlockCategory};
use crate::lists::{builtin_baseline_rules, load_cached_list, normalize_domain};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FilterDecision {
    Allow,
    Block {
        category: BlockCategory,
        matched_rule: String,
        list_name: String,
    },
}

#[derive(Debug, Clone)]
struct RuleMeta {
    category: BlockCategory,
    list_name: String,
}

#[derive(Default)]
struct EngineState {
    /// Blocked domains from subscribed lists + built-in baseline
    blocked_domains: HashMap<String, RuleMeta>,
    /// Exception domains from subscribed lists (@@||domain^)
    list_exceptions: HashSet<String>,
    /// User-defined allowlist domains (highest priority)
    user_allowlist: HashSet<String>,
    /// User-defined denylist domains
    user_denylist: HashSet<String>,
    /// Optional pause timestamp; while Utc::now() < paused_until, all requests are allowed
    paused_until: Option<DateTime<Utc>>,
}

pub struct FilterEngine {
    state: RwLock<EngineState>,
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterEngine {
    pub fn new() -> Self {
        let mut state = EngineState::default();
        Self::insert_baseline(&mut state);
        Self {
            state: RwLock::new(state),
        }
    }

    fn insert_baseline(state: &mut EngineState) {
        for (cat, domain, list_name) in builtin_baseline_rules() {
            state.blocked_domains.insert(
                domain.to_string(),
                RuleMeta {
                    category: cat,
                    list_name: list_name.to_string(),
                },
            );
        }
    }

    /// Rebuild the in-memory lookup tables from config + cached filter lists on disk.
    pub fn reload_from_config(&self, config: &AegisConfig, data_dir: &Path) -> usize {
        let mut next = EngineState::default();
        Self::insert_baseline(&mut next);

        // Preserve pause state across reloads
        if let Ok(guard) = self.state.read() {
            next.paused_until = guard.paused_until;
        }

        for list in config.lists.iter().filter(|l| l.enabled) {
            if let Some(parsed) = load_cached_list(list, data_dir) {
                for domain in parsed.blocked {
                    next.blocked_domains.entry(domain).or_insert_with(|| RuleMeta {
                        category: list.category,
                        list_name: list.name.clone(),
                    });
                }
                for domain in parsed.allowed {
                    next.list_exceptions.insert(domain);
                }
            }
        }

        for d in &config.allowlist {
            if let Some(norm) = normalize_domain(d) {
                next.user_allowlist.insert(norm);
            }
        }
        for d in &config.denylist {
            if let Some(norm) = normalize_domain(d) {
                next.user_denylist.insert(norm);
            }
        }

        let total = next.blocked_domains.len() + next.user_denylist.len();
        if let Ok(mut guard) = self.state.write() {
            *guard = next;
        }
        total
    }

    pub fn add_rule(&self, domain: &str, category: BlockCategory, list_name: &str) {
        if let Some(norm) = normalize_domain(domain) {
            if let Ok(mut guard) = self.state.write() {
                guard.blocked_domains.insert(
                    norm,
                    RuleMeta {
                        category,
                        list_name: list_name.to_string(),
                    },
                );
            }
        }
    }

    pub fn add_user_allow(&self, domain: &str) {
        if let Some(norm) = normalize_domain(domain) {
            if let Ok(mut guard) = self.state.write() {
                guard.user_denylist.remove(&norm);
                guard.user_allowlist.insert(norm);
            }
        }
    }

    pub fn add_user_deny(&self, domain: &str) {
        if let Some(norm) = normalize_domain(domain) {
            if let Ok(mut guard) = self.state.write() {
                guard.user_allowlist.remove(&norm);
                guard.user_denylist.insert(norm);
            }
        }
    }

    pub fn pause_for_seconds(&self, seconds: i64) {
        if let Ok(mut guard) = self.state.write() {
            guard.paused_until = Some(Utc::now() + chrono::Duration::seconds(seconds));
        }
    }

    pub fn resume(&self) {
        if let Ok(mut guard) = self.state.write() {
            guard.paused_until = None;
        }
    }

    pub fn paused_until(&self) -> Option<DateTime<Utc>> {
        self.state.read().ok().and_then(|g| {
            g.paused_until.filter(|t| *t > Utc::now())
        })
    }

    pub fn total_rules(&self) -> usize {
        self.state
            .read()
            .map(|g| g.blocked_domains.len() + g.user_denylist.len())
            .unwrap_or(0)
    }

    /// Evaluate a domain (including parent domain suffix matching) in O(labels).
    pub fn check_domain(&self, raw_host: &str) -> FilterDecision {
        // Strip port if present (e.g. "ads.example.com:443")
        let host_no_port = raw_host
            .split(':')
            .next()
            .unwrap_or(raw_host);

        let Some(domain) = normalize_domain(host_no_port) else {
            return FilterDecision::Allow;
        };

        let Ok(guard) = self.state.read() else {
            return FilterDecision::Allow;
        };

        // Check if protection is temporarily paused
        if let Some(until) = guard.paused_until {
            if Utc::now() < until {
                return FilterDecision::Allow;
            }
        }

        // 1. User allowlist has highest priority (exact or parent domain)
        if matches_set(&domain, &guard.user_allowlist) {
            return FilterDecision::Allow;
        }

        // 2. User denylist has second highest priority
        if let Some(matched) = find_in_set(&domain, &guard.user_denylist) {
            return FilterDecision::Block {
                category: BlockCategory::Custom,
                matched_rule: matched,
                list_name: "Custom Denylist".to_string(),
            };
        }

        // 3. List exception rules (@@||domain^)
        if matches_set(&domain, &guard.list_exceptions) {
            return FilterDecision::Allow;
        }

        // 4. Subscribed blocklists + built-in baseline (exact or parent domain)
        if let Some((matched, meta)) = find_in_map(&domain, &guard.blocked_domains) {
            return FilterDecision::Block {
                category: meta.category,
                matched_rule: matched,
                list_name: meta.list_name.clone(),
            };
        }

        FilterDecision::Allow
    }
}

fn matches_set(domain: &str, set: &HashSet<String>) -> bool {
    find_in_set(domain, set).is_some()
}

fn find_in_set(domain: &str, set: &HashSet<String>) -> Option<String> {
    let mut current = domain;
    loop {
        if set.contains(current) {
            return Some(current.to_string());
        }
        match current.find('.') {
            Some(idx) => current = &current[idx + 1..],
            None => return None,
        }
    }
}

fn find_in_map<'a>(domain: &str, map: &'a HashMap<String, RuleMeta>) -> Option<(String, &'a RuleMeta)> {
    let mut current = domain;
    loop {
        if let Some(meta) = map.get(current) {
            return Some((current.to_string(), meta));
        }
        match current.find('.') {
            Some(idx) => current = &current[idx + 1..],
            None => return None,
        }
    }
}
