use crate::events::{ClientStats, DomainCount, StatsSummary, TimelineBucket, TrafficEvent};
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

            CREATE TABLE IF NOT EXISTS clients (
                client TEXT PRIMARY KEY,
                total_requests INTEGER NOT NULL DEFAULT 0,
                blocked_requests INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
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

        // 3. Persist counters + domain count + per-client stats to SQLite
        if let Ok(conn) = self.conn.lock() {
            let res: rusqlite::Result<()> = (|| {
                increment_counter(&conn, "total_requests")?;
                let ts_str = event.timestamp.to_rfc3339();
                let is_blocked = matches!(event.decision, FilterDecision::Block { .. });
                let blocked_inc: i64 = if is_blocked { 1 } else { 0 };
                conn.execute(
                    "INSERT INTO clients (client, total_requests, blocked_requests, last_seen)
                     VALUES (?1, 1, ?2, ?3)
                     ON CONFLICT(client) DO UPDATE SET
                        total_requests = total_requests + 1,
                        blocked_requests = blocked_requests + excluded.blocked_requests,
                        last_seen = excluded.last_seen",
                    params![event.client, blocked_inc, ts_str],
                )?;
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

    pub fn client_stats(&self) -> Vec<ClientStats> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT client, total_requests, blocked_requests, last_seen
             FROM clients
             ORDER BY total_requests DESC
             LIMIT 100",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |row| {
            let total = row.get::<_, i64>(1)?.max(0) as u64;
            let blocked = row.get::<_, i64>(2)?.max(0) as u64;
            let rate = if total > 0 {
                ((blocked as f64 / total as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            };
            Ok(ClientStats {
                client: row.get(0)?,
                total_requests: total,
                blocked_requests: blocked,
                block_rate_percent: rate,
                last_seen: row.get(3)?,
            })
        }) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }

    pub fn query_log_count(&self) -> u64 {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.query_row("SELECT COUNT(*) FROM query_log", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0)
        .max(0) as u64
    }

    /// Prune old rows from `query_log` by age (`retention_days`, 0 = disabled)
    /// and by row cap (`max_rows`, 0 = disabled). Returns the number of deleted rows.
    pub fn prune_logs(&self, retention_days: u64, max_rows: u64) -> anyhow::Result<u64> {
        let mut deleted = 0u64;
        if let Ok(conn) = self.conn.lock() {
            if retention_days > 0 {
                let cutoff = (chrono::Utc::now()
                    - chrono::Duration::days(retention_days as i64))
                .to_rfc3339();
                let n = conn.execute(
                    "DELETE FROM query_log WHERE timestamp < ?1",
                    params![cutoff],
                )?;
                deleted += n as u64;
            }
            if max_rows > 0 {
                let n = conn.execute(
                    "DELETE FROM query_log
                     WHERE id NOT IN (
                         SELECT id FROM query_log ORDER BY id DESC LIMIT ?1
                     )",
                    params![max_rows as i64],
                )?;
                deleted += n as u64;
            }
        }
        Ok(deleted)
    }

    pub fn timeline_hourly(&self, hours: u32) -> Vec<TimelineBucket> {
        let hours = hours.clamp(1, 168);
        let now = chrono::Utc::now();
        let cutoff = (now - chrono::Duration::hours(hours as i64)).to_rfc3339();

        let mut counts: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::new();

        if let Ok(conn) = self.conn.lock() {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT substr(timestamp, 1, 13) AS hr,
                        COUNT(*) AS total,
                        SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked
                 FROM query_log
                 WHERE timestamp >= ?1
                 GROUP BY hr
                 ORDER BY hr ASC",
            ) {
                if let Ok(rows) = stmt.query_map(params![cutoff], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                }) {
                    for (hr, total, blocked) in rows.flatten() {
                        counts.insert(hr, (total, blocked));
                    }
                }
            }
        }

        // Fill all `hours` slots chronologically so the chart always has a continuous axis
        let mut out = Vec::with_capacity(hours as usize);
        for offset in (0..hours).rev() {
            let ts = now - chrono::Duration::hours(offset as i64);
            let key = ts.format("%Y-%m-%dT%H").to_string();
            let label = ts.format("%H:00").to_string();
            let (total, blocked) = counts.get(&key).copied().unwrap_or((0, 0));
            out.push(TimelineBucket {
                hour: label,
                total,
                blocked,
            });
        }
        out
    }

    pub fn reset_stats(&self) -> anyhow::Result<()> {
        if let Ok(mut buf) = self.recent.write() {
            buf.clear();
        }
        if let Ok(conn) = self.conn.lock() {
            conn.execute_batch(
                "DELETE FROM counters; DELETE FROM blocked_domains; DELETE FROM query_log; DELETE FROM clients;",
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
