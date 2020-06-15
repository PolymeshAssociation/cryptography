use log::info;
use metrics::Recorder;
use metrics_core::Key;

#[allow(dead_code)]
static RECORDER: PrintRecorder = PrintRecorder;

#[derive(Default)]
pub struct PrintRecorder;

impl Recorder for PrintRecorder {
    fn increment_counter(&self, key: Key, value: u64) {
        info!(
            "metrics: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }

    fn update_gauge(&self, key: Key, value: i64) {
        info!(
            "gauge: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }

    fn record_histogram(&self, key: Key, value: u64) {
        info!(
            "histogram: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }
}

#[cfg(feature = "std")]
pub fn init_print_logger() {
    let recorder = PrintRecorder::default();
    metrics::set_boxed_recorder(Box::new(recorder)).unwrap()
}

#[cfg(not(feature = "std"))]
pub fn init_print_logger() {
    metrics::set_recorder(&RECORDER).unwrap()
}
