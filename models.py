from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext

# Initialize FastAPI app
app = FastAPI(title="Patient Management System API")

# Security configurations
SECRET_KEY = "your-secure-secret-key"  # In production, use environment variables
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security contexts
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Data Models
class PatientBase(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    date_of_birth: str
    gender: str = Field(..., pattern="^(male|female|other)$")
    blood_type: Optional[str] = Field(None, pattern="^(A\+|A-|B\+|B-|AB\+|AB-|O\+|O-)$")
    medical_conditions: Optional[List[str]] = []

class PatientCreate(PatientBase):
    pass

class Patient(PatientBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UserInDB(BaseModel):
    username: str
    hashed_password: str
    is_active: bool = True
    is_admin: bool = False

# Mock database
patients_db = {}
users_db = {
    "admin": UserInDB(
        username="admin",
        hashed_password=pwd_context.hash("admin123"),
        is_admin=True
    ).dict()
}

# Authentication functions
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in users_db:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    return users_db[username]

# API Endpoints
@app.post("/token", response_model=dict)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/patients/", response_model=Patient, status_code=status.HTTP_201_CREATED)
async def create_patient(patient: PatientCreate, current_user: dict = Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized to create patients")
    
    patient_id = len(patients_db) + 1
    patient_dict = patient.dict()
    patient_dict.update({
        "id": patient_id,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })
    patients_db[patient_id] = patient_dict
    return patient_dict

@app.get("/patients/", response_model=List[Patient])
async def read_patients(
    skip: int = 0, 
    limit: int = 10, 
    current_user: dict = Depends(get_current_user)
):
    return list(patients_db.values())[skip : skip + limit]

@app.get("/patients/{patient_id}", response_model=Patient)
async def read_patient(patient_id: int, current_user: dict = Depends(get_current_user)):
    if patient_id not in patients_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Patient not found"
        )
    return patients_db[patient_id]

@app.put("/patients/{patient_id}", response_model=Patient)
async def update_patient(
    patient_id: int, 
    patient: PatientCreate, 
    current_user: dict = Depends(get_current_user)
):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized to update patients")
    
    if patient_id not in patients_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Patient not found"
        )
    
    patient_dict = patient.dict()
    patient_dict.update({
        "id": patient_id,
        "created_at": patients_db[patient_id]["created_at"],
        "updated_at": datetime.utcnow()
    })
    patients_db[patient_id] = patient_dict
    return patient_dict

@app.delete("/patients/{patient_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_patient(patient_id: int, current_user: dict = Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete patients")
    
    if patient_id not in patients_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Patient not found"
        )
    
    del patients_db[patient_id]