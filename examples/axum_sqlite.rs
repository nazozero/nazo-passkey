//! SQLite-backed Axum demo. Like `axum_server`, but credentials
//! persist across restarts in a local `passkeys.db` file.
//!
//! Run with:
//!     cargo run --example axum_sqlite
//!
//! Then open http://localhost:3000. Register a passkey, kill the
//! server, run it again - the passkey is still there.
//!
//! What this example demonstrates:
//!
//! - How to persist `PasskeyCredential` to a SQL row. The mapping is
//!   complete JSON credential is retained alongside indexed columns.
//!   Older rows migrate lazily without inventing UV or attestation trust.
//! - How to persist a verified outcome using a counter compare-and-swap
//!   BEFORE returning success. A stale snapshot cannot overwrite a newer one.
//! - Why challenge / session state is NOT in the DB: challenges are
//!   single-use and last ~60 seconds. Putting them in SQLite means
//!   you also need a cleanup job. In-memory + cookie sid is simpler.
//!
//! NOT FOR PRODUCTION: SQLite blocking IO from an async handler is
//! fine for a single-process demo; under real load use the `tokio-rusqlite`
//! crate or move to a real connection-pooled driver.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::post,
};
use rusqlite::{Connection, params};
use serde::Serialize;
use tokio::sync::Mutex;
// See axum_server.rs for why we do NOT install CorsLayer::permissive().
use tower_http::services::ServeDir;

use nazo_passkey::{
    Attachment, AttestationEvidence, AuthenticationResponse, AuthenticationState, CosePublicKey,
    CredentialId, PasskeyCredential, RegistrationResponse, RegistrationState, Webauthn,
};

const DB_PATH: &str = "passkeys.db";
const USERNAME: &str = "alice@example.com";

// ---------- storage layer --------------------------------------------------

/// The schema. One table per concept:
///   users      - (id BLOB PRIMARY KEY, username TEXT UNIQUE NOT NULL)
///   credentials - (id BLOB PK, user_id BLOB FK, public_key_cose BLOB,
///                  counter INTEGER, transports TEXT, aaguid BLOB,
///                  credential_json TEXT NULL for old rows)
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id        BLOB PRIMARY KEY,
    username  TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS credentials (
    id              BLOB PRIMARY KEY,
    user_id         BLOB NOT NULL,
    public_key_cose BLOB NOT NULL,
    counter         INTEGER NOT NULL,
    transports      TEXT NOT NULL,
    -- AAGUID is always 16 bytes per the WebAuthn spec. The CHECK
    -- constraint catches schema drift / manual edits at write time so
    -- the row_to_credential reader does not need to guess what a
    -- short value means.
    aaguid          BLOB NOT NULL CHECK (length(aaguid) = 16),
    credential_json TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"#;

struct Store {
    conn: Connection,
}

impl Store {
    fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        // Existing demo databases retain their original keys and indexed
        // columns. NULL marks metadata that was never recorded, not false.
        let has_json = {
            let mut query = conn.prepare("PRAGMA table_info(credentials)")?;
            let columns = query.query_map([], |row| row.get::<_, String>(1))?;
            columns
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|name| name == "credential_json")
        };
        if !has_json {
            conn.execute_batch("ALTER TABLE credentials ADD COLUMN credential_json TEXT;")?;
        }
        Ok(Self { conn })
    }

    /// Get or create the demo user. Returns the user_handle bytes.
    fn ensure_user(&self) -> rusqlite::Result<Vec<u8>> {
        let mut q = self
            .conn
            .prepare("SELECT id FROM users WHERE username = ?1")?;
        let mut rows = q.query(params![USERNAME])?;
        if let Some(row) = rows.next()? {
            return row.get::<_, Vec<u8>>(0);
        }
        drop(rows);
        drop(q);
        // First run: mint a fresh user_handle.
        let handle = {
            let mut buf = vec![0u8; 16];
            rand::fill(&mut buf);
            buf
        };
        self.conn.execute(
            "INSERT INTO users (id, username) VALUES (?1, ?2)",
            params![handle, USERNAME],
        )?;
        Ok(handle)
    }

    fn insert_credential(&self, user_id: &[u8], cred: &PasskeyCredential) -> rusqlite::Result<()> {
        let json = serde_json::to_string(cred)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        self.conn.execute(
            "INSERT INTO credentials (id, user_id, public_key_cose, counter, transports, aaguid, credential_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                cred.id.as_bytes(),
                user_id,
                cred.public_key_cose.as_bytes(),
                cred.counter,
                cred.transports.join(","),
                cred.aaguid,
                json,
            ],
        )?;
        Ok(())
    }

    fn list_credentials(&self, user_id: &[u8]) -> rusqlite::Result<Vec<PasskeyCredential>> {
        let mut q = self.conn.prepare(
            "SELECT id, public_key_cose, counter, transports, aaguid, credential_json, user_id
             FROM credentials WHERE user_id = ?1",
        )?;
        let creds = q
            .query_map(params![user_id], row_to_credential)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(creds)
    }

    fn find_credential(
        &self,
        user_id: &[u8],
        cred_id: &[u8],
    ) -> rusqlite::Result<Option<PasskeyCredential>> {
        let mut q = self.conn.prepare(
            "SELECT id, public_key_cose, counter, transports, aaguid, credential_json, user_id
             FROM credentials WHERE user_id = ?1 AND id = ?2",
        )?;
        let mut rows = q.query(params![user_id, cred_id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(row_to_credential(row)?));
        }
        Ok(None)
    }

    fn update_credential(
        &self,
        user_id: &[u8],
        previous: &PasskeyCredential,
        credential: &PasskeyCredential,
    ) -> rusqlite::Result<bool> {
        let json = serde_json::to_string(credential)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let changed = self.conn.execute(
            "UPDATE credentials SET counter = ?1, credential_json = ?2
             WHERE user_id = ?3 AND id = ?4 AND counter = ?5
               AND json_extract(credential_json, '$.backup_eligible') IS ?6
               AND json_extract(credential_json, '$.backup_state') IS ?7
               AND json_extract(credential_json, '$.uv_initialized') IS ?8",
            params![
                credential.counter,
                json,
                user_id,
                previous.id.as_bytes(),
                previous.counter,
                previous.backup_eligible,
                previous.backup_state,
                previous.uv_initialized,
            ],
        )?;
        Ok(changed == 1)
    }
}

fn row_to_credential(row: &rusqlite::Row<'_>) -> rusqlite::Result<PasskeyCredential> {
    let id: Vec<u8> = row.get(0)?;
    let pkc: Vec<u8> = row.get(1)?;
    let counter: u32 = row.get(2)?;
    let transports_csv: String = row.get(3)?;
    let aaguid_vec: Vec<u8> = row.get(4)?;
    let credential_json: Option<String> = row.get(5)?;
    let user_id: Vec<u8> = row.get(6)?;
    if let Some(json) = credential_json {
        let credential: PasskeyCredential = serde_json::from_str(&json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
        // Indexed columns and serialized state must describe the same key.
        if credential.id.as_bytes() != id
            || credential.public_key_cose.as_bytes() != pkc
            || credential.counter != counter
            || credential
                .user_handle
                .as_deref()
                .is_some_and(|handle| handle != user_id)
        {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                "credential JSON disagrees with indexed account/key/counter".into(),
            ));
        }
        return Ok(credential);
    }

    // The aaguid column is always 16 bytes. A row with a different
    // length means schema drift or a manually-edited DB - error rather
    // than silently zeroing it out, because [0u8; 16] is ALSO the
    // legitimate "no attestation, real AAGUID is all zeros" value
    // and conflating the two would let a corrupted row impersonate a
    // valid no-attestation credential.
    if aaguid_vec.len() != 16 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Blob,
            format!(
                "aaguid column wrong length: expected 16 bytes, got {}",
                aaguid_vec.len()
            )
            .into(),
        ));
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&aaguid_vec);

    Ok(PasskeyCredential {
        id: CredentialId(id),
        public_key_cose: CosePublicKey(pkc),
        counter,
        transports: if transports_csv.is_empty() {
            Vec::new()
        } else {
            transports_csv.split(',').map(|s| s.to_owned()).collect()
        },
        aaguid,
        user_handle: Some(user_id),
        uv_initialized: None,
        backup_eligible: None,
        backup_state: None,
        attestation: AttestationEvidence::Unknown,
    })
}

// ---------- in-memory ceremony state --------------------------------------

#[derive(Default)]
struct Session {
    reg_state: Option<RegistrationState>,
    auth_state: Option<AuthenticationState>,
}

struct AppState {
    store: Mutex<Store>,
    sessions: Mutex<HashMap<String, Session>>,
    wa: Webauthn,
}

// ---------- handlers ------------------------------------------------------

async fn register_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);
    let store = state.store.lock().await;
    let user_handle = store.ensure_user().map_err(db_err)?;
    let existing: Vec<_> = store
        .list_credentials(&user_handle)
        .map_err(db_err)?
        .into_iter()
        .map(|c| c.id)
        .collect();
    drop(store);

    let (challenge, reg_state) =
        state
            .wa
            .start_registration(&user_handle, USERNAME, "Alice", &existing);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .reg_state = Some(reg_state);

    Ok(json_with_sid(&challenge, &sid))
}

async fn register_finish(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<RegistrationResponse>,
) -> Result<Json<RegisterFinishReply>, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::BadRequest("missing sid cookie"))?;
    let reg_state = state
        .sessions
        .lock()
        .await
        .get_mut(&sid)
        .and_then(|s| s.reg_state.take())
        .ok_or(AppError::BadRequest("no registration in flight"))?;

    let credential = state
        .wa
        .finish_registration(&reg_state, &body)
        .map_err(|e| AppError::Unauthorized(format!("registration verify failed: {e}")))?;

    let store = state.store.lock().await;
    let user_handle = store.ensure_user().map_err(db_err)?;
    if user_handle != reg_state.user_id {
        return Err(AppError::BadRequest("registration account changed"));
    }
    store
        .insert_credential(&user_handle, &credential)
        .map_err(db_err)?;

    Ok(Json(RegisterFinishReply {
        ok: true,
        credential_id: credential.id.to_b64url(),
    }))
}

#[derive(Serialize)]
struct RegisterFinishReply {
    ok: bool,
    credential_id: String,
}

async fn authenticate_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);

    let store = state.store.lock().await;
    let user_handle = store.ensure_user().map_err(db_err)?;
    let creds = store.list_credentials(&user_handle).map_err(db_err)?;
    drop(store);
    if creds.is_empty() {
        return Err(AppError::BadRequest(
            "no registered credentials - register first",
        ));
    }

    // Use the for_user variant so finish_authentication can verify
    // the assertion's userHandle matches THIS user (WebAuthn-3 §7.2
    // step 6) — defence in depth against credential-id collisions in
    // a multi-user store.
    let (challenge, auth_state) = state
        .wa
        .start_authentication_with_creds_for_user(&user_handle, &creds);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .auth_state = Some(auth_state);

    Ok(json_with_sid(&challenge, &sid))
}

async fn authenticate_finish(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<AuthenticationResponse>,
) -> Result<Json<AuthFinishReply>, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::BadRequest("missing sid cookie"))?;
    let auth_state = state
        .sessions
        .lock()
        .await
        .get_mut(&sid)
        .and_then(|s| s.auth_state.take())
        .ok_or(AppError::BadRequest("no authentication in flight"))?;

    let asserted_id = CredentialId::from_b64url(&body.id)
        .map_err(|_| AppError::BadRequest("bad credential id"))?;
    let store = state.store.lock().await;
    let user_handle = auth_state
        .user_handle
        .as_deref()
        .ok_or(AppError::BadRequest("missing account binding"))?;
    let stored = store
        .find_credential(user_handle, asserted_id.as_bytes())
        .map_err(db_err)?
        .ok_or(AppError::Unauthorized("unknown credential".into()))?;

    let outcome = state
        .wa
        .finish_authentication(&auth_state, &body, &stored)
        .map_err(|e| AppError::Unauthorized(format!("auth verify failed: {e}")))?;

    // Preserve every verified metadata field; advancing the counter alone
    // would lose backup state and any known registration UV history.
    // Compare metadata as well: authenticators with a 0 -> 0 counter still
    // must not overwrite a newer backup/UV record from another process.
    let mut updated = stored.clone();
    updated.counter = outcome.new_counter;
    updated.backup_eligible = Some(outcome.backup_eligible);
    updated.backup_state = Some(outcome.backup_state);
    if !store
        .update_credential(user_handle, &stored, &updated)
        .map_err(db_err)?
    {
        return Err(AppError::Unauthorized(
            "credential changed concurrently".into(),
        ));
    }

    Ok(Json(AuthFinishReply {
        ok: true,
        user_verified: outcome.user_verified,
        new_counter: outcome.new_counter,
    }))
}

#[derive(Serialize)]
struct AuthFinishReply {
    ok: bool,
    user_verified: bool,
    new_counter: u32,
}

// ---------- helpers -------------------------------------------------------

fn get_or_create_sid(cookies: &HeaderMap) -> String {
    sid_from_cookies(cookies).unwrap_or_else(|| {
        let mut buf = [0u8; 16];
        rand::fill(&mut buf);
        hex::encode(buf)
    })
}

fn sid_from_cookies(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for cookie in raw.split(';') {
        let cookie = cookie.trim();
        if let Some(rest) = cookie.strip_prefix("sid=") {
            return Some(rest.to_owned());
        }
    }
    None
}

fn json_with_sid<T: Serialize>(body: &T, sid: &str) -> Response {
    let mut resp = Json(body).into_response();
    let cookie = format!("sid={sid}; HttpOnly; SameSite=Lax; Path=/");
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie ascii"),
    );
    resp
}

#[derive(Debug)]
enum AppError {
    BadRequest(&'static str),
    Unauthorized(String),
    Db(String),
}

fn db_err(e: rusqlite::Error) -> AppError {
    AppError::Db(e.to_string())
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.to_owned()),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            Self::Db(m) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {m}")),
        };
        (code, msg).into_response()
    }
}

// ---------- main ----------------------------------------------------------

#[tokio::main]
async fn main() {
    let store = Store::open(DB_PATH).expect("open SQLite");
    println!("opened SQLite at {DB_PATH}");
    let wa = Webauthn::new("localhost", "Passkey sqlite demo", "http://localhost:3000")
        .authenticator_attachment(Attachment::Any)
        .require_user_verification(false)
        .strict_base64(true);

    let state = Arc::new(AppState {
        store: Mutex::new(store),
        sessions: Mutex::new(HashMap::new()),
        wa,
    });

    let app = Router::new()
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/authenticate/start", post(authenticate_start))
        .route("/authenticate/finish", post(authenticate_finish))
        // Reuses the single-user HTML from the original axum_server example.
        .fallback_service(ServeDir::new("examples/static"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("sqlite demo listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(handle: &[u8]) -> PasskeyCredential {
        PasskeyCredential {
            id: CredentialId(vec![11; 16]),
            public_key_cose: CosePublicKey(vec![0xa1, 1, 2]),
            counter: 4,
            transports: vec!["usb".into()],
            aaguid: [3; 16],
            user_handle: Some(handle.to_vec()),
            uv_initialized: Some(true),
            backup_eligible: Some(true),
            backup_state: Some(false),
            attestation: AttestationEvidence::SelfAttestation,
        }
    }

    #[test]
    fn sqlite_cas_preserves_metadata_and_rejects_a_stale_counter() {
        let store = Store::open(":memory:").unwrap();
        let handle = store.ensure_user().unwrap();
        let initial = credential(&handle);
        store.insert_credential(&handle, &initial).unwrap();
        let mut accepted = initial.clone();
        accepted.counter = 5;
        accepted.backup_state = Some(true);
        assert!(
            store
                .update_credential(&handle, &initial, &accepted)
                .unwrap()
        );
        let mut stale = initial.clone();
        stale.counter = 6;
        assert!(!store.update_credential(&handle, &initial, &stale).unwrap());
        let loaded = store
            .find_credential(&handle, accepted.id.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.counter, 5);
        assert_eq!(loaded.uv_initialized, Some(true));
        assert_eq!(loaded.backup_state, Some(true));
        assert!(matches!(
            loaded.attestation,
            AttestationEvidence::SelfAttestation
        ));
        assert!(
            store
                .find_credential(b"other-user", accepted.id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sqlite_zero_counter_cas_cannot_overwrite_newer_metadata() {
        let store = Store::open(":memory:").unwrap();
        let handle = store.ensure_user().unwrap();
        let mut initial = credential(&handle);
        initial.counter = 0;
        initial.uv_initialized = None;
        initial.backup_eligible = None;
        initial.backup_state = None;
        store.insert_credential(&handle, &initial).unwrap();
        let mut first = initial.clone();
        first.uv_initialized = Some(true);
        first.backup_eligible = Some(true);
        first.backup_state = Some(true);
        assert!(store.update_credential(&handle, &initial, &first).unwrap());
        let mut stale = initial.clone();
        stale.uv_initialized = Some(false);
        stale.backup_eligible = Some(false);
        stale.backup_state = Some(false);
        assert!(!store.update_credential(&handle, &initial, &stale).unwrap());
        let loaded = store
            .find_credential(&handle, initial.id.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.counter, 0);
        assert_eq!(loaded.uv_initialized, Some(true));
        assert_eq!(loaded.backup_eligible, Some(true));
        assert_eq!(loaded.backup_state, Some(true));
    }

    #[test]
    fn sqlite_legacy_row_keeps_key_and_unknown_uv_history() {
        let path = std::env::temp_dir().join(format!(
            "passkey-auth-legacy-{}.sqlite",
            rand::random::<u128>()
        ));
        let handle = vec![12; 16];
        let initial = credential(&handle);
        {
            // Reopen an actual old database: this schema has no JSON column.
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE users (id BLOB PRIMARY KEY, username TEXT NOT NULL UNIQUE);
                 CREATE TABLE credentials (
                     id BLOB PRIMARY KEY, user_id BLOB NOT NULL,
                     public_key_cose BLOB NOT NULL, counter INTEGER NOT NULL,
                     transports TEXT NOT NULL,
                     aaguid BLOB NOT NULL CHECK (length(aaguid) = 16),
                     FOREIGN KEY (user_id) REFERENCES users(id)
                 );",
            )
            .unwrap();
            old.execute(
                "INSERT INTO users (id, username) VALUES (?1, ?2)",
                params![&handle, USERNAME],
            )
            .unwrap();
            // This is the exact old column projection, with the key already
            // persisted before Store::open performs the additive migration.
            old.execute(
                "INSERT INTO credentials (id, user_id, public_key_cose, counter, transports, aaguid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![initial.id.as_bytes(), &handle, initial.public_key_cose.as_bytes(),
                    initial.counter, "usb", &initial.aaguid],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.ensure_user().unwrap(), handle);
        let loaded = store
            .find_credential(&handle, initial.id.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.public_key_cose, initial.public_key_cose);
        assert_eq!(loaded.user_handle.as_deref(), Some(handle.as_slice()));
        assert_eq!(loaded.uv_initialized, None);
        assert_eq!(loaded.backup_eligible, None);
        assert_eq!(loaded.backup_state, None);
        assert!(matches!(loaded.attestation, AttestationEvidence::Unknown));
        assert!(store.update_credential(&handle, &loaded, &loaded).unwrap());
        let upgraded = store
            .find_credential(&handle, loaded.id.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(upgraded.public_key_cose, initial.public_key_cose);
        assert_eq!(upgraded.uv_initialized, None);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
