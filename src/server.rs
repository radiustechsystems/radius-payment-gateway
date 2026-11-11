//! The HTTP listeners: the proxy, which hands every request to a gate, and the admin listener.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use http::{HeaderMap, HeaderValue, Request, StatusCode};
use tokio::net::TcpListener;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

use crate::config::{Config, NoPolicy};
use crate::counters::MemoryStore;
use crate::error::error_response;
use crate::gate::{Gate, PaymentSettings};
use crate::pages::{ASSETS_PREFIX, Pages};
use crate::policy::{ACCEPTED_SCHEMAS, PlatformClient, PolicyHandle, Poller};
use crate::proxy::Upstream;
use crate::x402::FacilitatorClient;

/// Everything the listeners share. One gate per project; `select_gate` picks the project a
/// request belongs to. There is one project today.
pub struct AppState {
    pub gates: Vec<Arc<Gate>>,
    pub pollers: Vec<Arc<Poller>>,
    pub pages: Arc<Pages>,
}

impl AppState {
    /// Builds the gates and fetches each policy once, waiting up to `startup_policy_wait`.
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let required = config.required()?;
        tracing::info!(
            build = crate::build::ID,
            schemas = ACCEPTED_SCHEMAS.join(", "),
            project = %required.project_id,
            upstream = %required.upstream,
            "radius-gateway starting"
        );
        let pages = Arc::new(Pages::load(
            config.pages_dir.as_deref(),
            config.public_url.as_deref(),
        )?);
        let upstream = Upstream::new(
            required.upstream.clone(),
            config.upstream_connect_timeout,
            config.upstream_timeout,
        );
        let store = Arc::new(MemoryStore::new());
        store.spawn_sweeper(Duration::from_secs(60));

        let policy = Arc::new(PolicyHandle::default());
        let facilitator = Arc::new(FacilitatorClient::new(config.facilitator_timeout)?);
        let client = PlatformClient::new(
            &config.platform_api_url,
            required.platform_api_key.clone(),
            required.organization_id,
            required.project_id,
            Duration::from_secs(10),
        )?;
        let poller = Arc::new(Poller::new(
            client,
            policy.clone(),
            facilitator.clone(),
            config.poll_interval,
            required.project_id,
        ));
        let mut first_polled = false;
        if !config.startup_policy_wait.is_zero() {
            match tokio::time::timeout(config.startup_policy_wait, poller.poll_once()).await {
                Ok(_) => first_polled = true,
                Err(_) => tracing::warn!(
                    wait = ?config.startup_policy_wait,
                    "the first policy fetch didn't finish in time; serving under --no-policy until it does"
                ),
            }
        }
        tokio::spawn(poller.clone().run(!first_polled));

        let gate = Gate {
            policy,
            upstream,
            counters: store.clone(),
            claims: store.clone(),
            tickets: store,
            no_policy: config.no_policy,
            facilitator,
            pages: pages.clone(),
            payments: PaymentSettings {
                public_url: config.public_url.clone(),
                max_timeout_seconds: config.max_timeout_seconds,
                paid_body_limit: config.paid_body_limit,
                claim_ttl: config.claim_ttl,
                brand: config.brand.clone(),
                brand_url: config.brand_url.clone(),
                ticket_ttl: config.ticket_ttl,
            },
        };
        Ok(Self {
            gates: vec![Arc::new(gate)],
            pollers: vec![poller],
            pages,
        })
    }

    fn select_gate(&self, _request: &Request<Body>) -> &Arc<Gate> {
        &self.gates[0]
    }
}

/// The proxy: every path, every method, except the pages' own assets, which are answered here
/// before any policy sees them.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(&format!("{ASSETS_PREFIX}/{{*path}}"), get(asset))
        .fallback(handle)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state)
}

async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    let gate = state.select_gate(&request).clone();
    gate.handle(request, peer).await
}

/// A page asset: cacheable, with an ETag.
async fn asset(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(asset) = state.pages.asset(&path) else {
        return error_response(StatusCode::NOT_FOUND, "not_found", "no such asset");
    };
    let unchanged = headers
        .get(IF_NONE_MATCH)
        .is_some_and(|value| value == asset.etag);
    let mut response = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, asset.body.clone()).into_response()
    };
    let h = response.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
    h.insert(ETAG, asset.etag.clone());
    h.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Health and policy status, on a listener of its own so it never shadows an upstream path.
pub fn admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/version", get(version))
        .route("/readyz", get(ready))
        .route("/policy", get(policy_status))
        .route("/policy/refresh", post(policy_refresh))
        .with_state(state)
}

/// Ready once a policy is loaded, or at once when requests pass through without one.
async fn ready(State(state): State<Arc<AppState>>) -> Response {
    let ready = state
        .gates
        .iter()
        .all(|gate| gate.policy.load().is_some() || gate.no_policy == NoPolicy::Allow);
    if ready {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "waiting for the policy").into_response()
    }
}

async fn policy_status(State(state): State<Arc<AppState>>) -> Response {
    let mut snapshot = state.gates[0].policy.snapshot();
    snapshot["build"] = crate::build::ID.into();
    axum::Json(snapshot).into_response()
}

/// Which code this is.
async fn version() -> Response {
    axum::Json(serde_json::json!({
        "name": "radius-gateway",
        "version": crate::build::VERSION,
        "commit": crate::build::COMMIT,
        "build": crate::build::ID,
    }))
    .into_response()
}

/// Fetches the policy now, outside the schedule, and reports the outcome and the status.
async fn policy_refresh(State(state): State<Arc<AppState>>) -> Response {
    let outcome = match state.pollers[0].poll_once().await {
        Ok(polled) => format!("{polled:?}"),
        Err(error) => format!("error: {error}"),
    };
    let mut snapshot = state.gates[0].policy.snapshot();
    snapshot["refresh"] = outcome.into();
    axum::Json(snapshot).into_response()
}

/// The gateway, bound and ready to serve.
pub struct App {
    state: Arc<AppState>,
    listener: TcpListener,
    admin_listener: TcpListener,
}

impl App {
    pub async fn bind(config: &Config) -> anyhow::Result<Self> {
        let state = Arc::new(AppState::new(config).await?);
        let listener = TcpListener::bind(config.listen).await?;
        let admin_listener = TcpListener::bind(config.admin_listen).await?;
        Ok(Self {
            state,
            listener,
            admin_listener,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has an address")
    }

    pub fn admin_addr(&self) -> SocketAddr {
        self.admin_listener
            .local_addr()
            .expect("a bound listener has an address")
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    /// Serves until `shutdown` completes, then finishes in-flight requests.
    pub async fn serve<F>(self, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown.await;
            let _ = tx.send(true);
        });
        let wait = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|stopped| *stopped).await;
        };
        tracing::info!(listen = %self.addr(), admin = %self.admin_addr(), "listening");
        let proxy = axum::serve(
            self.listener,
            router(self.state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait(rx.clone()));
        let admin = axum::serve(self.admin_listener, admin_router(self.state.clone()))
            .with_graceful_shutdown(wait(rx));
        tokio::try_join!(proxy, admin)?;
        Ok(())
    }
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler installs");
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
