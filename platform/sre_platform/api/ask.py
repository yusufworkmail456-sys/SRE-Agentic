"""Ask Agent API + UI fragment (HTMX)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..askagent import ask
from ..db import get_db
from ..models import Application

router = APIRouter(prefix="/api/ask", tags=["ask"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "ui" / "templates"))


def _get_app(db: Session, slug: str) -> Application:
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return app_row


@router.post("/{slug}")
def ask_api(slug: str, body: dict, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    question = str(body.get("question", "")).strip()
    if not question:
        raise HTTPException(422, "question required")
    result = ask(db, app_row, question, history=body.get("history"))
    db.commit()
    return result


@router.post("/{slug}/html", response_class=HTMLResponse)
def ask_html(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    question: str = Form(""),
):
    app_row = _get_app(db, slug)
    if not question.strip():
        return HTMLResponse("")
    result = ask(db, app_row, question.strip())
    db.commit()
    return templates.TemplateResponse(
        request, "_ask_answer.html", {"result": result, "question": question.strip()}
    )
