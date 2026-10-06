"""Read-only local console (M6, FR-19): runs, run detail, gate, recommendations, verdicts.

Security posture (docs/THREAT_MODEL.md "Console exposed on network"):
- every route is GET and read-only: no state changes, so no CSRF surface;
- no JavaScript at all: server-rendered Jinja2 (autoescape on) + inline SVG charts, which
  allows a strict CSP (script-src 'none') and needs no CDN;
- Host header allowlist against DNS rebinding of the localhost service;
- security headers on every response; the CLI binds to 127.0.0.1 by default.
"""

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from clawshield import __version__
from clawshield.config import DEFAULT_CONFIG_PATH, Settings, load_settings
from clawshield.core.score import SliceScore
from clawshield.redteam.corpus import CorpusError
from clawshield.scoring import RunScore, ScoringError, gate_run, score_run, to_dict
from clawshield.storage.db import RunNotFoundError, Store
from clawshield.tuner.recommend import recommend_suppressions

HERE = Path(__file__).parent
TREND_RUNS = 20
ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")  # DNS-rebinding defence
MAX_TEXT = 200

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self' data:; "
        "script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@dataclass(frozen=True)
class Bar:
    label: str
    value: float | None
    low: float | None
    high: float | None
    n: int


def _bars(rows: list[SliceScore], *, use_fpr: bool) -> list[Bar]:
    bars = []
    for s in rows:
        value, ci = (s.fpr, s.fpr_ci) if use_fpr else (s.recall, s.recall_ci)
        n = s.negatives if use_fpr else s.positives
        if n:
            bars.append(Bar(s.value, value, ci.low if ci else None, ci.high if ci else None, n))
    return bars


def _failing_cases(rs: RunScore) -> list[dict[str, Any]]:
    outcomes = {o.case_id: o for o in rs.card.outcomes}
    leaked = set(rs.card.leaked_case_ids)
    failing = []
    for item in rs.inputs:
        o = outcomes.get(item.case.id)
        missed = o is not None and o.label == "malicious" and not o.detected
        false_positive = o is not None and o.label == "benign" and o.detected
        if missed or false_positive or item.case.id in leaked:
            failing.append(
                {
                    "id": item.case.id,
                    "kind": "miss" if missed else ("false positive" if false_positive else "leak"),
                    "category": item.case.category.value,
                    "severity": item.case.expected_severity.value,
                    "leaked": item.case.id in leaked,
                    "text": item.case.text[:MAX_TEXT],
                    "truncated": len(item.case.text) > MAX_TEXT,
                }
            )
    return failing


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(
        title="ClawShield console", version=__version__,
        docs_url=None, redoc_url=None, openapi_url=None,
    )  # fmt: skip
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.autoescape = True
    templates.env.globals.update(
        version=__version__,
        recall_target=settings.gate.min_critical_recall,
        fpr_target=settings.gate.max_benign_block_fpr,
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return templates.TemplateResponse(
            request, "error.html", {"status_code": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )  # fmt: skip

    def store() -> Store | None:
        path = settings.storage.db_path
        return Store(path) if path.exists() else None

    def scored(run_id: str) -> RunScore:
        s = store()
        if s is None:
            raise HTTPException(404, "no runs yet")
        try:
            return score_run(s, settings, run_id)
        except RunNotFoundError:
            raise HTTPException(404, f"run {run_id!r} not found") from None
        except (ScoringError, CorpusError) as exc:
            raise HTTPException(409, str(exc)) from None

    def page(request: Request, name: str, **context: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, context)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/runs", status_code=303)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/runs", response_class=HTMLResponse)
    def runs(request: Request) -> HTMLResponse:
        s = store()
        return page(request, "runs.html", listings=s.list_runs(100) if s else [])

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: str) -> HTMLResponse:
        rs = scored(run_id)
        return page(
            request, "run.html", rs=rs, card=rs.card,
            recall_bars=_bars(rs.card.dimension("category"), use_fpr=False),
            fpr_bars=_bars(rs.card.dimension("category"), use_fpr=True),
            failing=_failing_cases(rs),
        )  # fmt: skip

    @app.get("/runs/{run_id}/gate", response_class=HTMLResponse)
    def gate(request: Request, run_id: str) -> HTMLResponse:
        rs = scored(run_id)
        s = store()
        if s is None:
            raise HTTPException(404, "no runs yet")
        _, report = gate_run(s, settings, rs.run.id)
        return page(request, "gate.html", rs=rs, report=report)

    @app.get("/runs/{run_id}/recommendations", response_class=HTMLResponse)
    def recommendations(request: Request, run_id: str) -> HTMLResponse:
        rs = scored(run_id)
        recs = recommend_suppressions(
            rs.inputs, rs.verdicts, detected_min=settings.scoring.detected_min_severity,
            connector=settings.defenseclaw.connector,
        )  # fmt: skip
        return page(request, "recommendations.html", rs=rs, recs=recs)

    @app.get("/verdicts", response_class=HTMLResponse)
    def verdicts(request: Request) -> HTMLResponse:
        s = store()
        return page(request, "verdicts.html", verdicts=s.recent_verdicts(200) if s else [])

    @app.get("/trend", response_class=HTMLResponse)
    def trend(request: Request) -> HTMLResponse:
        s = store()
        points = []
        for listing in reversed(s.list_runs(TREND_RUNS) if s else []):
            if not listing.complete:
                continue
            try:
                o = score_run(s, settings, listing.run.id).card.overall  # type: ignore[arg-type]
            except (ScoringError, CorpusError):
                continue  # e.g. corpus edited since that run: skip rather than mis-score
            points.append({"id": listing.run.id, "recall": o.recall, "fpr": o.fpr})
        return page(request, "trend.html", points=points)

    @app.get("/api/runs/{run_id}/score")
    def api_score(run_id: str) -> JSONResponse:
        return JSONResponse(to_dict(scored(run_id), settings))

    return app


def _load_app() -> FastAPI:
    """Entry point for `uvicorn clawshield.console.app:app`; CLAWSHIELD_CONFIG overrides."""
    return create_app(load_settings(Path(os.environ.get("CLAWSHIELD_CONFIG", DEFAULT_CONFIG_PATH))))


def __getattr__(name: str) -> Any:  # lazy: importing the module must not read config
    if name == "app":
        return _load_app()
    raise AttributeError(name)
