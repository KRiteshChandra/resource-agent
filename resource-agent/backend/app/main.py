"""
main.py  (FINAL version: replaces the earlier one)
-------
FastAPI entrypoint for the AI Resource Acquisition Agent backend.

Run from the `backend/` folder:
    uvicorn app.main:app --reload --port 8000

Then open http://127.0.0.1:8000/docs
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Load GITHUB_TOKEN / HF_TOKEN etc. from backend/.env if it exists. Tokens are optional.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    logging.getLogger(__name__).warning(
        "python-dotenv is not installed, so .env was not loaded (run: pip install -r requirements.txt)")

from app.database import init_db
from app.routers import approvals, downloads, requirements, resources

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AI Resource Acquisition Agent",
    version="0.1.0",
    description="Discovers, ranks, and gates approval/download of external resources.",
    lifespan=lifespan,
)

# Allow the local React dev server (Vite) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


app.include_router(requirements.router)   # POST/GET /requests
app.include_router(resources.router)      # GET /requests/{id}/resources
app.include_router(approvals.router)      # POST /resources/{id}/approve
app.include_router(downloads.router)      # POST /resources/{id}/download, GET /downloads/{id}[/report]
