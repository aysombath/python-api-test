from contextlib import asynccontextmanager

from fastapi import FastAPI

from python_api.auth import router as auth_router
from python_api.bootstrap import seed_permissions, seed_sysadmin
from python_api.db import init_db
from python_api.role_permissions import router as role_permissions_router
from python_api.users import router as users_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_permissions()
    await seed_sysadmin()
    yield


app = FastAPI(title="python-api", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(role_permissions_router)


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Hello from python-api!"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
