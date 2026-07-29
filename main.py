from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from src.database import SessionLocal, init_db
from src.exceptions import MiniVaultError, error_response
from src.routers import auth_router, vault_router, transit_router


def create_app() -> FastAPI:
    app = FastAPI(title="Mini Vault", version="0.1.0")
    from src.database import Base, get_engine

    engine = get_engine()
    SessionLocal.configure(bind=engine)
    Base.metadata.create_all(bind=engine)
    init_db(engine)

    @app.exception_handler(MiniVaultError)
    async def mini_vault_error_handler(
        request: Request, exc: MiniVaultError
    ) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=error_response(exc))

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": {"code": "VALIDATION_ERROR", "message": "Validation failed."}
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_error_handler(
        request: Request, exc: SQLAlchemyError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "DATABASE_ERROR", "message": "Database error."}},
        )

    app.include_router(vault_router)
    app.include_router(auth_router)
    app.include_router(transit_router)
    return app


app = create_app()
