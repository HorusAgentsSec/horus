from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.api.router import api_router
from backend.core import scheduler
from backend.core import executor
from backend.core.config import settings
from backend.core.rate_limit import build_limiter, client_ip_from
from backend.core.security_headers import build_security_headers

if settings.sentry_dsn:
    import sentry_sdk

    # Auto-instruments FastAPI/Starlette (unhandled request exceptions) since both are
    # installed. Agent-pipeline errors are caught and logged, not raised, so they're
    # reported explicitly at the catch site (backend/agents/pipeline.py) instead.
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        traces_sample_rate=settings.sentry_traces_sample_rate,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.start()
    yield
    scheduler.stop()
    executor.shutdown()


app = FastAPI(
    title="Horus API",
    version="0.1.0",
    lifespan=lifespan,
)

# ── Rate limiting ────────────────────────────────────────────────────────────────
# Registered before CORS so CORS ends up the outermost layer — that way even a 429
# carries CORS headers and the browser can read it.
# Uses Redis when REDIS_URL is set (shared across workers); falls back to in-memory.
_limiter = build_limiter(settings.redis_url)
# Write-heavy / abuse-prone endpoints get a tighter per-IP budget.
_SENSITIVE_ROUTES = (
    ("POST", "/api/scans"),
    ("POST", "/api/team/invite"),
)


def _too_many(retry_after: float) -> JSONResponse:
    seconds = max(1, round(retry_after))
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Slow down."},
        headers={"Retry-After": str(seconds)},
    )


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if not settings.rate_limit_enabled or not request.url.path.startswith("/api"):
        return await call_next(request)

    ip = client_ip_from(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        settings.trust_proxy_headers,
    )

    allowed, retry = _limiter.hit(ip, settings.rate_limit_per_minute)
    if not allowed:
        return _too_many(retry)

    for method, prefix in _SENSITIVE_ROUTES:
        if request.method == method and request.url.path.startswith(prefix):
            allowed, retry = _limiter.hit(f"{ip}:sensitive", settings.rate_limit_sensitive_per_minute)
            if not allowed:
                return _too_many(retry)
            break

    return await call_next(request)


# ── Security headers ─────────────────────────────────────────────────────────────
_SECURITY_HEADERS = build_security_headers(settings.environment)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health")
def health():
    return {"status": "ok"}
