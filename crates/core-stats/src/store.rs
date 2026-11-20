use crate::events::{DomainCount, StatsSummary, TrafficEvent};
use core_engine::{BlockCategory, FilterDecision};
use rusqlite::{params, Connection};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use tokio::sync::broadcast;
use tracing::warn;

const RING_CAPACITY: usize = 500;

pub struct StatsStore {
    conn: Mutex<Connection>,
    recent: RwLock<VecDeque<TrafficEvent>>,
    tx: broadcast::Sender<TrafficEvent>,
}

impl StatsStore {
    pub fn open(db_path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)?;
        Self::init(conn)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS counters (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS blocked_domains (
                domain TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS query_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                protocol TEXT NOT NULL,
                domain TEXT NOT NULL,
                client TEXT NOT NULL,
                action TEXT NOT NULL,
                category TEXT,
                list_name TEXT,
                latency_ms INTEGER NOT NULL
            );
            ",
        )?;

        let (tx, _) = broadcast::channel(256);
        Ok(Self {
            conn: Mutex::new(conn),
            recent: RwLock::new(VecDeque::with_capacity(RING_CAPACITY)),
            tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TrafficEvent> {
        self.tx.subscribe()
    }

    pub fn record(&self, event: TrafficEvent) {
        // 1. Push to in-memory ring buffer
        if let Ok(mut buf) = self.recent.write() {
            if buf.len() >= RING_CAPACITY {
                buf.pop_back();
            }
            buf.push_front(event.clone());
        }

        // 2. Broadcast to live WebSocket listeners
        let _ = self.tx.send(event.clone());

        // 3. Persist counters + domain count to SQLite
        if let Ok(conn) = self.conn.lock() {
            let res: rusqlite::Result<()> = (|| {
                increment_counter(&conn, "total_requests")?;
                match &event.decision {
                    FilterDecision::Allow => {
                        conn.execute(
                            "INSERT INTO query_log (timestamp, protocol, domain, client, action, category, list_name, latency_ms)
                             VALUES (?1, ?2, ?3, ?4, 'allow', NULL, NULL, ?5)",
                            params![
                                event.timestamp.to_rfc3339(),
                                event.protocol.as_str(),
                                event.domain,
                                event.client,
                                event.latency_ms as i64,
                            ],
                        )?;
                    }
                    FilterDecision::Block {
                        category,
                        list_name,
                        ..
                    } => {
                        increment_counter(&conn, "total_blocked")?;
                        let cat_key = match category {
                            BlockCategory::Ad => "ads_blocked",
                            BlockCategory::Tracker => "trackers_blocked",
                            BlockCategory::WindowsTelemetry => "windows_telemetry_blocked",
                            BlockCategory::MacOSTelemetry => "macos_telemetry_blocked",
                            BlockCategory::Malware => "malware_blocked",
                            BlockCategory::Custom => "custom_blocked",
                        };
                        increment_counter(&conn, cat_key)?;

                        conn.execute(
                            "INSERT INTO blocked_domains (domain, category, count)
                             VALUES (?1, ?2, 1)
                             ON CONFLICT(domain) DO UPDATE SET count = count + 1, category = excluded.category",
                            params![event.domain, category.as_str()],
                        )?;

                        conn.execute(
                            "INSERT INTO query_log (timestamp, protocol, domain, client, action, category, list_name, latency_ms)
                             VALUES (?1, ?2, ?3, ?4, 'block', ?5, ?6, ?7)",
                            params![
                                event.timestamp.to_rfc3339(),
                                event.protocol.as_str(),
                                event.domain,
                                event.client,
                                category.as_str(),
                                list_name,
                                event.latency_ms as i64,
                            ],
                        )?;
                    }
                }
                Ok(())
            })();

            if let Err(e) = res {
                warn!(error = %e, "Failed to persist traffic event to SQLite");
            }
        }
    }

    pub fn summary(&self) -> StatsSummary {
        let mut s = StatsSummary::default();
        let Ok(conn) = self.conn.lock() else {
            return s;
        };

        if let Ok(mut stmt) = conn.prepare("SELECT key, value FROM counters") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    let val = row.1.max(0) as u64;
                    match row.0.as_str() {
                        "total_requests" => s.total_requests = val,
                        "total_blocked" => s.total_blocked = val,
                        "ads_blocked" => s.ads_blocked = val,
                        "trackers_blocked" => s.trackers_blocked = val,
                        "windows_telemetry_blocked" => s.windows_telemetry_blocked = val,
                        "macos_telemetry_blocked" => s.macos_telemetry_blocked = val,
                        "malware_blocked" => s.malware_blocked = val,
                        "custom_blocked" => s.custom_blocked = val,
                        _ => {}
                    }
                }
            }
        }

        if s.total_requests > 0 {
            s.block_rate_percent =
                ((s.total_blocked as f64 / s.total_requests as f64) * 1000.0).round() / 10.0;
        }

        if let Ok(mut stmt) = conn.prepare(
            "SELECT domain, count, category FROM blocked_domains ORDER BY count DESC LIMIT 10",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(DomainCount {
                    domain: row.get(0)?,
                    count: row.get::<_, i64>(1)?.max(0) as u64,
                    category: row.get(2)?,
                })
            }) {
                s.top_blocked_domains = rows.flatten().collect();
            }
        }

        s
    }

    pub fn recent_logs(&self, limit: usize) -> Vec<TrafficEvent> {
        self.recent
            .read()
            .map(|buf| buf.iter().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    pub fn reset_stats(&self) -> anyhow::Result<()> {
        if let Ok(mut buf) = self.recent.write() {
            buf.clear();
        }
        if let Ok(conn) = self.conn.lock() {
            conn.execute_batch(
                "DELETE FROM counters; DELETE FROM blocked_domains; DELETE FROM query_log;",
            )?;
        }
        Ok(())
    }
}

fn increment_counter(conn: &Connection, key: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO counters (key, value) VALUES (?1, 1)
         ON CONFLICT(key) DO UPDATE SET value = value + 1",
        params![key],
    )?;
    Ok(())
}
