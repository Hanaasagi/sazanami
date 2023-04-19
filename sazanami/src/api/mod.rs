use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio_metrics::{RuntimeMetrics, TaskMetrics};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing_subscriber::registry;

use crate::metrics::{self, get_metrics_registry};

// FIXME: serde remote is not work?
// https://serde.rs/remote-derive.html
#[derive(Serialize)]
struct TaskMetricsDef {
    pub instrumented_count: u64,
    pub dropped_count: u64,
    pub first_poll_count: u64,
    pub total_first_poll_delay: Duration,
    pub total_idled_count: u64,
    pub total_idle_duration: Duration,
    pub total_scheduled_count: u64,
    pub total_scheduled_duration: Duration,
    pub total_poll_count: u64,
    pub total_poll_duration: Duration,
    pub total_fast_poll_count: u64,
    pub total_fast_poll_duration: Duration,
    pub total_slow_poll_count: u64,
    pub total_slow_poll_duration: Duration,
    pub total_short_delay_count: u64,
    pub total_long_delay_count: u64,
    pub total_short_delay_duration: Duration,
    pub total_long_delay_duration: Duration,
}

impl From<TaskMetrics> for TaskMetricsDef {
    fn from(item: TaskMetrics) -> Self {
        Self {
            instrumented_count: item.instrumented_count,
            dropped_count: item.dropped_count,
            first_poll_count: item.first_poll_count,
            total_first_poll_delay: item.total_first_poll_delay,
            total_idled_count: item.total_idled_count,
            total_idle_duration: item.total_idle_duration,
            total_scheduled_count: item.total_scheduled_count,
            total_scheduled_duration: item.total_scheduled_duration,
            total_poll_count: item.total_poll_count,
            total_poll_duration: item.total_poll_duration,
            total_fast_poll_count: item.total_fast_poll_count,
            total_fast_poll_duration: item.total_fast_poll_duration,
            total_slow_poll_count: item.total_slow_poll_count,
            total_slow_poll_duration: item.total_slow_poll_duration,
            total_short_delay_count: item.total_short_delay_count,
            total_long_delay_count: item.total_long_delay_count,
            total_short_delay_duration: item.total_short_delay_duration,
            total_long_delay_duration: item.total_long_delay_duration,
        }
    }
}
#[derive(Serialize)]
struct RuntimeMetricsDef {
    pub workers_count: usize,
    pub total_park_count: u64,
    pub max_park_count: u64,
    pub min_park_count: u64,
    pub total_noop_count: u64,
    pub max_noop_count: u64,
    pub min_noop_count: u64,
    pub total_steal_count: u64,
    pub max_steal_count: u64,
    pub min_steal_count: u64,
    pub total_steal_operations: u64,
    pub max_steal_operations: u64,
    pub min_steal_operations: u64,
    pub num_remote_schedules: u64,
    pub total_local_schedule_count: u64,
    pub max_local_schedule_count: u64,
    pub min_local_schedule_count: u64,
    pub total_overflow_count: u64,
    pub max_overflow_count: u64,
    pub min_overflow_count: u64,
    pub total_polls_count: u64,
    pub max_polls_count: u64,
    pub min_polls_count: u64,
    pub total_busy_duration: Duration,
    pub max_busy_duration: Duration,
    pub min_busy_duration: Duration,
    pub injection_queue_depth: usize,
    pub total_local_queue_depth: usize,
    pub max_local_queue_depth: usize,
    pub min_local_queue_depth: usize,
    pub elapsed: Duration,
    pub budget_forced_yield_count: u64,
    pub io_driver_ready_count: u64,
}
impl From<RuntimeMetrics> for RuntimeMetricsDef {
    fn from(item: RuntimeMetrics) -> Self {
        Self {
            workers_count: item.workers_count,
            total_park_count: item.total_park_count,
            max_park_count: item.max_park_count,
            min_park_count: item.min_park_count,
            total_noop_count: item.total_noop_count,
            max_noop_count: item.max_noop_count,
            min_noop_count: item.min_noop_count,
            total_steal_count: item.total_steal_count,
            max_steal_count: item.max_steal_count,
            min_steal_count: item.min_steal_count,
            total_steal_operations: item.total_steal_operations,
            max_steal_operations: item.max_steal_operations,
            min_steal_operations: item.min_steal_operations,
            num_remote_schedules: item.num_remote_schedules,
            total_local_schedule_count: item.total_local_schedule_count,
            max_local_schedule_count: item.max_local_schedule_count,
            min_local_schedule_count: item.min_local_schedule_count,
            total_overflow_count: item.total_overflow_count,
            max_overflow_count: item.max_overflow_count,
            min_overflow_count: item.min_overflow_count,
            total_polls_count: item.total_polls_count,
            max_polls_count: item.max_polls_count,
            min_polls_count: item.min_polls_count,
            total_busy_duration: item.total_busy_duration,
            max_busy_duration: item.max_busy_duration,
            min_busy_duration: item.min_busy_duration,
            injection_queue_depth: item.injection_queue_depth,
            total_local_queue_depth: item.total_local_queue_depth,
            max_local_queue_depth: item.max_local_queue_depth,
            min_local_queue_depth: item.min_local_queue_depth,
            elapsed: item.elapsed,
            budget_forced_yield_count: item.budget_forced_yield_count,
            io_driver_ready_count: item.io_driver_ready_count,
        }
    }
}

#[derive(Serialize)]
pub struct Metrics {
    runtime: RuntimeMetricsDef,
    tasks: HashMap<String, TaskMetricsDef>,
}
pub struct ApiServer {
    /// Listen address
    listen_at: SocketAddr,
    service: Router,
}

impl ApiServer {
    pub async fn new(listen_at: SocketAddr) -> Self {
        let router = Router::new().route("/metrics", get(metrics));

        Self {
            listen_at,
            service: router,
        }
    }

    pub async fn serve(self) -> anyhow::Result<()> {
        axum::Server::bind(&self.listen_at)
            .serve(self.service.into_make_service())
            .await?;
        Ok(())
    }

    pub fn listen_at(&self) -> SocketAddr {
        self.listen_at
    }
}

async fn metrics() -> Result<Json<Metrics>, (StatusCode, &'static str)> {
    let mut registry = metrics::get_metrics_registry().lock().await;
    let mut tasks = HashMap::new();

    if let Some(metrics) = registry.get_metrics("proxy").await {
        tasks.insert("proxy".to_owned(), metrics.into());
    } else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Could not fetch metrics"));
    }

    if let Some(metrics) = registry.get_metrics("dns").await {
        tasks.insert("dns".to_owned(), metrics.into());
    } else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Could not fetch metrics"));
    }

    if let Some(metrics) = registry.get_runtime_metrics().await {
        return Ok(Json(Metrics {
            runtime: metrics.into(),
            tasks,
        }));
    } else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Could not fetch metrics"));
    }
}
