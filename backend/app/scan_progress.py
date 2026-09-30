"""Request-local progress events; ordinary JSON clients incur no extra work."""
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar

_listener = ContextVar("scan_progress_listener", default=None)


@contextmanager
def listen(callback):
    token = _listener.set(callback)
    try:
        yield
    finally:
        _listener.reset(token)


async def report(stage, label, detail="", status="running"):
    callback = _listener.get()
    if callback:
        await callback({"stage": stage, "label": label, "detail": detail, "status": status})


@asynccontextmanager
async def step(stage, label, detail=""):
    await report(stage, label, detail)
    try:
        yield
    except Exception:
        await report(stage, label, status="unavailable")
        raise
    else:
        await report(stage, label, status="complete")
