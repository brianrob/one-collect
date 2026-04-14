// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[derive(Default)]
pub struct EventExtension {
    /// Optional perf filter expression to be applied to this
    /// event's perf file descriptors.
    perf_filter: Option<String>,
}

impl EventExtension {
    pub fn perf_filter(&self) -> Option<&str> {
        self.perf_filter.as_deref()
    }

    pub fn set_perf_filter(&mut self, filter: impl Into<String>) {
        self.perf_filter = Some(filter.into());
    }

    /// Clears any previously set perf tracepoint filter.
    pub fn clear_perf_filter(&mut self) {
        self.perf_filter = None;
    }
}
