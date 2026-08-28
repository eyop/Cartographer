from fastapi import FastAPI

from .routers import health, investigations

app = FastAPI(
    title="Cartographer",
    version="0.1.0",
    description="Aggregates OSINT signals and synthesizes them into structured threat profiles.",
)

app.include_router(health.router)
app.include_router(investigations.router)
