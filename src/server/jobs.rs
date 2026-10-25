//! Background jobs with a persisted log, one at a time per app.
use anyhow::{bail, Result};
use std::future::Future;
use std::sync::Arc;

use super::db;
use super::state::Shared;

#[derive(Clone)]
pub struct Log {
    db: db::Db,
    pub job_id: i64,
    redact: Arc<Vec<String>>,
}

impl Log {
    pub fn new(db: db::Db, job_id: i64, redact: Vec<String>) -> Self {
        Log { db, job_id, redact: Arc::new(redact.into_iter().filter(|s| s.len() >= 4).collect()) }
    }

    pub fn redact(&self, line: &str) -> String {
        let mut l = line.to_string();
        for s in self.redact.iter() {
            if l.contains(s.as_str()) {
                l = l.replace(s.as_str(), "[redacted]");
            }
        }
        l
    }

    pub async fn line(&self, line: impl AsRef<str>) {
        let l = self.redact(line.as_ref());
        tracing::info!(job = self.job_id, "{l}");
        if let Err(e) = db::job_append_log(&self.db, self.job_id, &l).await {
            tracing::warn!("job log: {e}");
        }
    }
}

/// Start a job unless one is already active for the app. Returns the job id.
pub async fn spawn<F, Fut>(state: &Shared, kind: &str, app_id: Option<i64>, redact: Vec<String>, f: F) -> Result<i64>
where
    F: FnOnce(Shared, Log) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    if let Some(id) = app_id {
        if let Some(j) = db::active_job_of(&state.db, id).await? {
            bail!("job {} ({}) is still running for this app", j.id, j.kind);
        }
    }
    let job_id = db::create_job(&state.db, kind, app_id).await?;
    let st = state.clone();
    let log = Log::new(state.db.clone(), job_id, redact);
    tokio::spawn(async move {
        let _ = db::job_set_status(&st.db, job_id, "running").await;
        let result = f(st.clone(), log.clone()).await;
        match result {
            Ok(()) => {
                let _ = db::job_set_status(&st.db, job_id, "done").await;
            }
            Err(e) => {
                log.line(format!("error: {e:#}")).await;
                let _ = db::job_set_status(&st.db, job_id, "failed").await;
            }
        }
    });
    Ok(job_id)
}
