pub(crate) mod bindings;

use std::{
    ffi,
    ptr::{self, NonNull},
    slice,
    sync::Arc,
};

macro_rules! debug_println {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*)
        }
    };
}

#[repr(u32)]
pub enum ConfigProperty {
    Service = bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_SERVICE_NAME,
    Env = bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_ENV,
    Version = bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_VERSION,
    AgentUrl = bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_AGENT_URL,
}

#[repr(u32)]
enum InternalConfig {
    LibraryVersion = bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_LIBRARY_VERSION,
    LibraryLanguage = bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_LIBRARY_LANGUAGE,
    LanguageVersion =
        bindings::datadog_sdk_tracer_option_DATADOG_TRACER_OPT_LIBRARY_LANGUAGE_VERSION,
}

pub struct Config {
    inner: NonNull<bindings::datadog_sdk_conf_t>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            inner: unsafe {
                NonNull::new(bindings::datadog_sdk_tracer_conf_new())
                    .expect("Datadog configuration should not be null")
            },
        }
    }

    pub fn set(&mut self, property: ConfigProperty, value: &str) {
        let mut value = str_to_ffi_view(value);
        unsafe {
            bindings::datadog_sdk_tracer_conf_set(
                self.inner.as_ptr(),
                property as bindings::datadog_sdk_tracer_option,
                &mut value as *mut bindings::str_view as *mut ffi::c_void,
            )
        }
    }

    fn set_internal(&mut self, property: InternalConfig, value: &str) {
        let mut value = str_to_ffi_view(value);
        unsafe {
            bindings::datadog_sdk_tracer_conf_set(
                self.inner.as_ptr(),
                property as bindings::datadog_sdk_tracer_option,
                &mut value as *mut bindings::str_view as *mut ffi::c_void,
            )
        }
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        unsafe { bindings::datadog_sdk_tracer_conf_free(self.inner.as_ptr()) }
    }
}

struct TracerInner(NonNull<bindings::datadog_sdk_tracer_t>);

impl Drop for TracerInner {
    fn drop(&mut self) {
        eprintln!("freeing the tracer");
        unsafe { bindings::datadog_sdk_tracer_free(self.0.as_ptr()) };
    }
}

// The Tracer is thread safe
unsafe impl Send for TracerInner {}
unsafe impl Sync for TracerInner {}

#[derive(Clone)]
pub struct Tracer {
    inner: Option<Arc<TracerInner>>,
}

impl Tracer {
    pub fn new_noop() -> Self {
        Self { inner: None }
    }

    pub fn new(mut cfg: Config) -> Self {
        cfg.set_internal(InternalConfig::LibraryLanguage, "rust");
        cfg.set_internal(InternalConfig::LibraryVersion, "0.0.1");
        cfg.set_internal(
            InternalConfig::LanguageVersion,
            crate::build_info::rust_version(),
        );

        // TODO(paullgdc): should we log something or return an error when the tracer is null?
        let inner = NonNull::new(unsafe { bindings::datadog_sdk_tracer_new(cfg.inner.as_ptr()) });
        if inner.is_none() {
            debug_println!("ddtrace-rust: datadog_sdk_tracer_new returned null");
        }
        Tracer {
            inner: inner.map(|t| Arc::new(TracerInner(t.cast()))),
        }
    }

    pub fn create_span(&self, name: &str) -> Span {
        let Some(tracer) = &self.inner else {
            return Span::new_noop();
        };
        let name = str_to_ffi_view(name);
        Span {
            inner: unsafe {
                NonNull::new(bindings::datadog_sdk_tracer_create_span(
                    tracer.0.as_ptr(),
                    name,
                ))
            },
        }
    }

    pub fn create_or_extract_span<'a, F: FnMut(&str) -> Option<&'a [u8]> + 'a>(
        &self,
        mut reader: F,
        name: &str,
        ressource: &str,
    ) -> Span {
        let Some(tracer) = self.inner.as_ref().map(|t| t.as_ref().0.as_ptr()) else {
            return Span::new_noop();
        };

        let name = str_to_ffi_view(name);
        let resource = str_to_ffi_view(ressource);
        unsafe extern "C" fn reader_fn_trampoline<'a, F: FnMut(&str) -> Option<&'a [u8]> + 'a>(
            ctx: *mut ffi::c_void,
            key: bindings::str_view,
        ) -> bindings::str_view {
            let Some(f) = (ctx as *mut F ).as_mut() else {
                return bindings::str_view {
                    buf: std::ptr::null_mut(),
                    len: 0,
                };
            };
            let key = ffi_view_to_slice(&key);
            let Ok(key) = std::str::from_utf8(key)  else {
                return bindings::str_view {
                    buf: ptr::null_mut(),
                    len: 0,
                };
            };
            match f(key) {
                Some(value) => str_to_ffi_view(value),
                None => bindings::str_view {
                    buf: ptr::null_mut(),
                    len: 0,
                },
            }
        }

        let ctx: *mut ffi::c_void = &mut reader as *mut F as *mut ffi::c_void;

        let inner = NonNull::new(unsafe {
            bindings::datadog_sdk_tracer_extract_or_create_span(
                tracer,
                ctx,
                Some(reader_fn_trampoline::<F>),
                name,
                resource,
            )
        });
        if inner.is_none() {
            debug_println!(
                "ddtrace-rust: datadog_sdk_tracer_extract_or_create_span returned a null span"
            );
        }
        Span { inner }
    }

    pub fn flush(&self) {
        let Some(tracer) = self.inner.as_ref().map(|t| t.as_ref().0.as_ptr()) else {
            return ;
        };
        unsafe {
            bindings::datadog_sdk_tracer_flush(tracer);
        }
    }
}

#[derive(Debug)]
pub struct Span {
    inner: Option<NonNull<bindings::datadog_sdk_span_t>>,
}

impl Drop for Span {
    fn drop(&mut self) {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return ;
        };
        unsafe {
            bindings::datadog_sdk_span_finish(inner);
            bindings::datadog_sdk_span_free(inner);
        };
    }
}

// Span objects are thread safe
unsafe impl Send for Span {}
unsafe impl Sync for Span {}

impl Span {
    pub fn new_noop() -> Self {
        Self { inner: None }
    }

    pub fn set_type(&mut self, span_type: &str) {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return ;
        };
        let span_type = str_to_ffi_view(span_type);
        unsafe { bindings::datadog_sdk_span_set_type(inner, span_type) }
    }

    pub fn set_tag(&mut self, tag: &str, value: &str) {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return ;
        };
        let tag = str_to_ffi_view(tag);
        let value = str_to_ffi_view(value);
        unsafe { bindings::datadog_sdk_span_set_tag(inner, tag, value) }
    }

    pub fn set_error(&mut self, is_err: bool) {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return ;
        };
        unsafe { bindings::datadog_sdk_span_set_error(inner, is_err as ffi::c_int) }
    }

    pub fn set_error_message(&mut self, message: &str) {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return ;
        };
        let message = str_to_ffi_view(message);
        unsafe { bindings::datadog_sdk_span_set_error_message(inner, message) }
    }

    pub fn create_child(&self, name: &str) -> Self {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return Span::new_noop();
        };
        let name = str_to_ffi_view(name);
        Self {
            inner: NonNull::new(unsafe { bindings::datadog_sdk_span_create_child(inner, name) }),
        }
    }

    pub fn inject<F: FnMut(&[u8], &[u8])>(&self, mut writer: F) {
        let Some(inner) = self.inner.map(NonNull::as_ptr) else {
            return ;
        };

        unsafe extern "C" fn writer_trampoline<F: FnMut(&[u8], &[u8])>(
            ctx: *mut ffi::c_void,
            key: bindings::str_view,
            value: bindings::str_view,
        ) {
            let Some(f) = (ctx as *mut F).as_mut() else {
                return
            };
            f(ffi_view_to_slice(&key), ffi_view_to_slice(&value));
        }
        let ctx = &mut writer as *mut F as *mut ffi::c_void;
        unsafe { bindings::datadog_sdk_span_inject(inner, ctx, Some(writer_trampoline::<F>)) }
    }
}

fn str_to_ffi_view<T: AsRef<[u8]>>(s: T) -> bindings::str_view {
    bindings::str_view {
        buf: s.as_ref().as_ptr().cast::<ffi::c_char>(),
        len: s.as_ref().len(),
    }
}
unsafe fn ffi_view_to_slice(s: &bindings::str_view) -> &[u8] {
    if s.buf.is_null() {
        slice::from_raw_parts(std::ptr::NonNull::dangling().as_ptr(), s.len)
    } else {
        slice::from_raw_parts(s.buf.cast::<u8>(), s.len)
    }
}
