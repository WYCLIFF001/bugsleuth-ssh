use anyhow::{Result, Context};
use rusqlite::{Connection};
use std::path::Path;

/// User record from database (with max_logins for abuse control)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DbUser {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub created_date: String,
    pub expiry_date: String,
    pub max_logins: u32,
}

/// Initialize database schema (adds max_logins to your table)
pub fn init_db(path: &Path) -> Result<()> {
    let conn = Connection::open(path)
        .context("Failed to open database")?;

    // This matches your table structure with max_logins added
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ssh (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            max_logins INTEGER NOT NULL DEFAULT 1
        )",
        [],
    ).context("Failed to create table")?;

    // Create index for faster lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_username ON ssh(username)",
        [],
    ).context("Failed to create index")?;

    Ok(())
}

/// Migrate existing table to add max_logins column
pub fn migrate_add_max_logins(path: &Path) -> Result<()> {
    let conn = Connection::open(path)?;

    // Check if column exists
    let mut stmt = conn.prepare("PRAGMA table_info(ssh)")?;
    let columns: Vec<String> = stmt.query_map([], |row| row.get(1))?
        .collect::<Result<Vec<_>, _>>()?;

    if !columns.contains(&"max_logins".to_string()) {
        conn.execute(
            "ALTER TABLE ssh ADD COLUMN max_logins INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
        tracing::info!("Added max_logins column to existing table");
    }

    Ok(())
}

/// Load all active (non-expired) users from database
pub fn load_enabled_users(path: &Path) -> Result<Vec<DbUser>> {
    let conn = Connection::open(path)
        .context("Failed to open database")?;

    // Get current date/time for expiry check
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut stmt = conn.prepare(
        "SELECT id, username, password, created_date, expiry_date, max_logins
         FROM ssh
         WHERE expiry_date > ?1
         ORDER BY id"
    )?;

    let users = stmt.query_map([&now], |row| {
        Ok(DbUser {
            id: row.get(0)?,
            username: row.get(1)?,
            password: row.get(2)?,
            created_date: row.get(3)?,
            expiry_date: row.get(4)?,
            max_logins: row.get(5)?,
        })
    })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(users)
}
