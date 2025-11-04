from fastapi import FastAPI, Request, Depends, HTTPException, Form, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import json
import secrets
from datetime import datetime, timedelta
from app.database import get_db, init_db
from app.models import User, OAuth2Client, AuthorizationCode, AccessToken
from app.auth import (
    hash_password,
    authenticate_user,
    create_access_token,
    get_current_user,
)
from config import FIXED_APPS


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown (if needed)


app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# Check if setup needed
def needs_setup(db: Session):
    return db.query(User).filter(User.role == "super_admin").count() == 0


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    if needs_setup(db):
        return templates.TemplateResponse("setup.html", {"request": request})
    return templates.TemplateResponse("home.html", {"request": request})


@app.post("/setup")
def setup_super_admin(
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...),
    register_mdx: bool = Form(False),
    register_gdx: bool = Form(False),
    db: Session = Depends(get_db),
):
    if not needs_setup(db):
        raise HTTPException(status_code=400, detail="Setup already done")
    # Create super admin
    hashed_pw = hash_password(password)
    super_admin = User(
        username=username, email=email, hashed_password=hashed_pw, role="super_admin"
    )
    db.add(super_admin)
    # Register selected apps
    if register_mdx:
        client_id = secrets.token_urlsafe(16)
        client_secret = secrets.token_urlsafe(32)
        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            app_name="mdx",
            redirect_uris=json.dumps(FIXED_APPS["mdx"]["redirect_uris"]),
        )
        db.add(client)
    if register_gdx:
        client_id = secrets.token_urlsafe(16)
        client_secret = secrets.token_urlsafe(32)
        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            app_name="gdx",
            redirect_uris=json.dumps(FIXED_APPS["gdx"]["redirect_uris"]),
        )
        db.add(client)
    db.commit()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid credentials"}
        )
    token = create_access_token({"sub": user.username})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    hashed_pw = hash_password(password)
    user = User(username=username, email=email, hashed_password=hashed_pw)
    db.add(user)
    db.commit()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")
    user = get_current_user(token, db)
    if not user:
        return RedirectResponse(url="/login")
    clients = db.query(OAuth2Client).all() if user.role == "super_admin" else []
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "user": user, "clients": clients}
    )


# OAuth2 endpoints
@app.get("/oauth/authorize")
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    state: str = None,
    db: Session = Depends(get_db),
):
    # Check client
    client = db.query(OAuth2Client).filter(OAuth2Client.client_id == client_id).first()
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")
    # Redirect to login if not authenticated
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url=f"/login?next={request.url}")
    user = get_current_user(token, db)
    if not user:
        return RedirectResponse(url=f"/login?next={request.url}")
    # Show consent page
    return templates.TemplateResponse(
        "authorize.html",
        {
            "request": request,
            "client": client,
            "redirect_uri": redirect_uri,
            "state": state,
        },
    )


@app.post("/oauth/authorize")
def authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(None),
    approve: bool = Form(False),
    db: Session = Depends(get_db),
):
    token = request.cookies.get("access_token")
    user = get_current_user(token, db)
    if approve:
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db.add(auth_code)
        db.commit()
        redirect_url = (
            f"{redirect_uri}?code={code}&state={state}"
            if state
            else f"{redirect_uri}?code={code}"
        )
        return RedirectResponse(url=redirect_url)
    else:
        return RedirectResponse(url=f"{redirect_uri}?error=access_denied")


@app.post("/oauth/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: Session = Depends(get_db),
):
    # Validate code
    auth_code = (
        db.query(AuthorizationCode).filter(AuthorizationCode.code == code).first()
    )
    if not auth_code or auth_code.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid code")
    client = (
        db.query(OAuth2Client)
        .filter(
            OAuth2Client.client_id == client_id,
            OAuth2Client.client_secret == client_secret,
        )
        .first()
    )
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")
    # Issue token
    access_token = create_access_token(
        {"sub": auth_code.user_id, "client_id": client_id}
    )
    token_entry = AccessToken(
        token=access_token,
        client_id=client_id,
        user_id=auth_code.user_id,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )
    db.add(token_entry)
    db.delete(auth_code)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}


# Placeholder for MDX/GDX integration
@app.get("/signin-with-idp")
def signin_with_idp(client_id: str):
    # Redirect to authorize endpoint
    return RedirectResponse(
        url=f"/oauth/authorize?client_id={client_id}&redirect_uri=http://localhost:8001/auth/callback&response_type=code"
    )
