from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from models import User, Contact
from schemas import UserCreate, ContactCreate, ContactUpdate
from database import get_db

SECRET_KEY = "your_secret_key"  # Змініть на свій секретний ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 днів

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return email

def register_user(user: UserCreate, db: Session):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")
    
    hashed_password = pwd_context.hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def login_user(user: UserCreate, db: Session):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    return {"access_token": access_token, "refresh_token": refresh_token}

def create_contact(contact: ContactCreate, current_user: str, db: Session):
    db_contact = Contact(**contact.dict(), user_email=current_user)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(current_user: str, db: Session):
    return db.query(Contact).filter(Contact.user_email == current_user).all()

def update_contact(contact_id: int, contact: ContactUpdate, current_user: str, db: Session):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_email == current_user).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    
    for key, value in contact.dict(exclude_unset=True).items():
        setattr(db_contact, key, value)
    
    db.commit()
    db.refresh(db_contact)
    return db_contact

def delete_contact(contact_id: int, current_user: str, db: Session):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_email == current_user).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    
    db.delete(db_contact)
    db.commit()
    return {"ok": True}

def search_contacts(first_name: str, last_name: str, email: str, current_user: str, db: Session):
    query = db.query(Contact).filter(Contact.user_email == current_user)
    if first_name:
        query = query.filter(Contact.first_name.ilike(f"%{first_name}%"))
    if last_name:
        query = query.filter(Contact.last_name.ilike(f"%{last_name}%"))
    if email:
        query = query.filter(Contact.email.ilike(f"%{email}%"))
    
    return query.all()

def get_upcoming_birthdays(current_user: str, db: Session):
    today = datetime.utcnow().date()
    next_week = today + timedelta(days=7)
    return db.query(Contact).filter(Contact.birthday.between(today, next_week), Contact.user_email == current_user).all()