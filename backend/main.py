from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import json
import time
from contextlib import asynccontextmanager
import jwt
from passlib.context import CryptContext

DATABASE_URL = "postgresql://user:password@db:5432/secops_db"

SECRET_KEY = "secops-orchestrator-super-secret-key-xyz-123"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


# Initialize engine lazily to avoid startup errors
engine = None
SessionLocal = None
Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    scanner = Column(String)
    severity = Column(String)
    type = Column(String)
    description = Column(String)
    project = Column(String)
    repository = Column(String)
    branch = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="developer")  # admin, developer, auditor


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, SessionLocal
    # Wait for database to be ready
    for i in range(60):
        try:
            engine = create_engine(DATABASE_URL, pool_pre_ping=True)
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            # Test connection
            db = SessionLocal()
            db.execute(text("SELECT 1"))
            db.close()
            Base.metadata.create_all(bind=engine)
            print("Database connected and tables created")
            break
        except Exception as e:
            print(f"Waiting for database... attempt {i+1}/60: {e}")
            time.sleep(3)
    yield
    if engine:
        engine.dispose()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt_token(data: dict) -> str:
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None

class UserSignup(BaseModel):
    username: str
    email: str
    password: str
    role: str = "developer"

class UserSignin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True

class ScanResult(BaseModel):
    scanner: str
    timestamp: str
    findings: List[Dict]

class VulnerabilityInput(BaseModel):
    scanner: str
    severity: str
    type: str
    description: str
    project: str
    repository: str
    branch: str

class FeedbackRequest(BaseModel):
    vulnerability_id: int
    platform: str  # jira, github
    issue_url: str
    remediation_advice: str

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserResponse:
    token = credentials.credentials
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role
        )
    finally:
        db.close()

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: UserResponse = Depends(get_current_user)):
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=403, 
                detail=f"Operation not permitted. Required roles: {self.allowed_roles}. Your role: {current_user.role}"
            )
        return current_user

# API Endpoints
@app.post("/scan-results/")
async def ingest_scan_results(result: ScanResult):
    db = SessionLocal()
    try:
        for finding in result.findings:
            vulnerability = Vulnerability(
                scanner=result.scanner,
                severity=finding.get("severity"),
                type=finding.get("type"),
                description=finding.get("description"),
                project=finding.get("project"),
                repository=finding.get("repository"),
                branch=finding.get("branch")
            )
            db.add(vulnerability)
        db.commit()
        return {"message": "Scan results ingested successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/auth/signup", response_model=UserResponse)
async def signup(user_in: UserSignup):
    db = SessionLocal()
    try:
        existing_user = db.query(User).filter((User.username == user_in.username) | (User.email == user_in.email)).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username or email already registered")
        
        if user_in.role not in ["admin", "developer", "auditor"]:
            raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin', 'developer', or 'auditor'")

        new_user = User(
            username=user_in.username,
            email=user_in.email,
            hashed_password=hash_password(user_in.password),
            role=user_in.role
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    finally:
        db.close()

@app.post("/auth/signin")
async def signin(user_in: UserSignin):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == user_in.username).first()
        if not user or not verify_password(user_in.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        
        token = create_jwt_token({"sub": user.username, "role": user.role})
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        }
    finally:
        db.close()

@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: UserResponse = Depends(get_current_user)):
    return current_user


@app.get("/dashboard/vulnerabilities/")
async def get_dashboard_vulnerabilities(
    severity: Optional[str] = None, 
    project: Optional[str] = None,
    current_user: UserResponse = Depends(get_current_user)
):
    db = SessionLocal()
    try:
        query = db.query(Vulnerability)
        if severity:
            query = query.filter(Vulnerability.severity == severity)
        if project:
            query = query.filter(Vulnerability.project == project)
        results = query.all()
        return {
            "vulnerabilities": [
                {
                    "id": v.id,
                    "scanner": v.scanner,
                    "severity": v.severity,
                    "type": v.type,
                    "description": v.description,
                    "project": v.project,
                    "repository": v.repository,
                    "branch": v.branch,
                    "created_at": v.created_at.isoformat()
                } for v in results
            ]
        }
    finally:
        db.close()

@app.get("/dashboard/stats/")
async def get_dashboard_stats(current_user: UserResponse = Depends(get_current_user)):
    db = SessionLocal()
    try:
        total = db.query(Vulnerability).count()
        critical = db.query(Vulnerability).filter(Vulnerability.severity == "CRITICAL").count()
        high = db.query(Vulnerability).filter(Vulnerability.severity == "HIGH").count()
        medium = db.query(Vulnerability).filter(Vulnerability.severity == "MEDIUM").count()
        low = db.query(Vulnerability).filter(Vulnerability.severity == "LOW").count()
        return {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        }
    finally:
        db.close()

@app.post("/policies/check/")
async def check_policies(project: str, branch: str):
    db = SessionLocal()
    try:
        critical_findings = db.query(Vulnerability).filter(
            Vulnerability.project == project,
            Vulnerability.branch == branch,
            Vulnerability.severity == "CRITICAL"
        ).count()
        return {
            "passed": critical_findings == 0,
            "critical_findings": critical_findings
        }
    finally:
        db.close()

@app.post("/feedback/")
async def create_feedback(
    feedback: FeedbackRequest,
    current_user: UserResponse = Depends(RoleChecker(["admin", "developer"]))
):
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == feedback.vulnerability_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        # In production: integrate with Jira/GitHub APIs
        return {
            "message": f"Feedback created for vulnerability {feedback.vulnerability_id}",
            "platform": feedback.platform,
            "issue_url": feedback.issue_url,
            "remediation": feedback.remediation_advice
        }
    finally:
        db.close()

@app.get("/remediation/")
async def get_remediation_guide(
    severity: str, 
    vuln_type: str,
    current_user: UserResponse = Depends(get_current_user)
):
    # Simplified remediation advice - in production this would pull from OWASP/etc.
    remediation_db = {
        "CRITICAL": {
            "SQL Injection": "Use parameterized queries, input validation",
            "XSS": "Sanitize inputs, use Content Security Policy",
            "Command Injection": "Avoid shell commands, use safe APIs"
        },
        "HIGH": {
            "Insecure Dependencies": "Update to patched versions, use SCA tools",
            "Missing Authentication": "Implement proper auth, use MFA"
        }
    }
    return {
        "severity": severity,
        "type": vuln_type,
        "advice": remediation_db.get(severity, {}).get(vuln_type, "Review OWASP guidelines for remediation")
    }

@app.get("/")
async def read_root():
    return {"message": "Welcome to SecOps Orchestrator Backend"}
