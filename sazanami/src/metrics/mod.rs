use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// use tokio::sync::OnceCell;
use once_cell::sync::OnceCell;
use tokio::sync::Mutex;
use tokio_metrics::{RuntimeIntervals, RuntimeMetrics, TaskMetrics, TaskMonitor};

static INSTANCE: OnceCell<Mutex<MetricsRegistry>> = OnceCell::new();

pub struct MetricsRegistry {
    monitors: HashMap<String, TaskMonitor>,
    generators: HashMap<String, Mutex<Box<dyn Iterator<Item = TaskMetrics> + Sync + Send>>>,
    runtime: RuntimeIntervals,
}

impl fmt::Debug for MetricsRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsRegistry")
            .field("monitors", &self.monitors)
            .finish()
    }
}

impl MetricsRegistry {
    fn new() -> Self {
        let handle = tokio::runtime::Handle::current();
        let runtime_monitor = tokio_metrics::RuntimeMonitor::new(&handle);
        Self {
            monitors: HashMap::new(),
            generators: HashMap::new(),
            runtime: runtime_monitor.intervals(),
        }
    }

    pub fn add(&mut self, name: &str, monitor: TaskMonitor) {
        let generator =
            Mutex::new(Box::new(monitor.intervals())
                as Box<dyn Iterator<Item = TaskMetrics> + Send + Sync>);
        self.monitors.insert(name.to_string(), monitor.clone());
        self.generators.insert(name.to_string(), generator);
    }

    pub fn remove(&mut self, name: &str) {
        self.monitors.remove(name);
        self.generators.remove(name);
    }

    pub async fn get_metrics(&mut self, name: &str) -> Option<TaskMetrics> {
        match self.generators.get_mut(name) {
            Some(gen) => gen.lock().await.next(),
            None => None,
        }
    }

    pub async fn get_runtime_metrics(&mut self) -> Option<RuntimeMetrics> {
        self.runtime.next()
    }
}

pub fn setup_metrics_registry() {
    let registry = Mutex::new(MetricsRegistry::new());
    INSTANCE
        .set(registry)
        .expect("failed to setup metrics registry");
}

pub fn get_metrics_registry() -> &'static Mutex<MetricsRegistry> {
    INSTANCE.get().expect("failed to get metrics registry")
}
