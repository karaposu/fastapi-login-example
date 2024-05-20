import os
import uvicorn
import jwt
import smtplib
import logging
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_login import LoginManager
from fastapi_login.exceptions import InvalidCredentialsException
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = FastAPI()

SECRET = os.getenv("SECRET_KEY")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
if not SECRET or not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    raise ValueError("SECRET_KEY, EMAIL_ADDRESS, and EMAIL_PASSWORD must be set in environment variables")

manager = LoginManager(SECRET, token_url='/v1/auth/login')


@manager.user_loader
def load_user(email: str):
    logging.debug(f"Loading user: {email}")
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    db.close()
    if user:
        logging.debug(f"User {email} found in database")
    else:
        logging.debug(f"User {email} not found in database")
    return user


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True, index=True)
    hashed_password = Column(String)
    is_verified = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordModel(BaseModel):
    old_password: str
    new_password: str


class ResetPasswordModel(BaseModel):
    email: EmailStr
    new_password: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def send_verification_email(email: str, token: str):
    verification_link = f"http://127.0.0.1:8000/v1/auth/verify-email?token={token}"
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email
    msg['Subject'] = 'Email Verification'
    body = f"Please verify your email by clicking the following link: {verification_link}"
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.office365.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            logging.debug(f"Verification email sent to {email}")
    except smtplib.SMTPAuthenticationError as e:
        logging.error(f"SMTP Authentication Error: {e}")
        raise HTTPException(status_code=500, detail="SMTP Authentication Error")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send email")


@app.post('/v1/auth/register')
def register(user: UserCreate, db: Session = Depends(get_db)):
    logging.debug(f"Attempting to register user: {user.email}")
    try:
        valid = validate_email(user.email)
        email = valid.email
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))

    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        logging.debug(f"User {user.email} already exists")
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, is_verified=False)
    db.add(db_user)
    db.commit()

    # Generate verification token
    token = manager.create_access_token(data={'sub': user.email})
    send_verification_email(user.email, token)

    logging.debug(f"User {user.email} registered successfully, verification email sent")
    return {"msg": "User registered successfully, please verify your email"}


@app.get('/v1/auth/verify-email')
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        email = payload['sub']
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        user.is_verified = True
        db.commit()
        return {"msg": "Email verified successfully"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Verification link expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid verification link")


@app.post('/v1/auth/login')
def login(data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = data.username
    password = data.password
    user = db.query(User).filter(User.email == email).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise InvalidCredentialsException
    if not user.is_verified:
        raise HTTPException(status_code=400, detail="Email not verified")
    access_token = manager.create_access_token(data={'sub': email})
    logging.debug(f"Generated access token for user {email}: {access_token}")
    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/v1/auth/private')
def logged_in_users_only(user=Depends(manager)):
    logging.debug(f"Accessing private route with user: {user.email}")
    if not user:
        logging.debug("User not found or invalid JWT token")
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {'message': f'Hello, {user.email}'}


@app.post('/v1/auth/change-password')
def change_password(data: ChangePasswordModel, user=Depends(manager), db: Session = Depends(get_db)):
    logging.debug(f"Changing password for user: {user.email}")
    logging.debug(f"Old password provided: {data.old_password}")
    logging.debug(f"New password provided: {data.new_password}")
    if not pwd_context.verify(data.old_password, user.hashed_password):
        logging.debug("Old password does not match")
        raise HTTPException(status_code=400, detail="Invalid password")
    user.hashed_password = pwd_context.hash(data.new_password)
    db.add(user)
    db.commit()
    return {"msg": "Password changed successfully"}


@app.post('/v1/auth/reset-password')
def reset_password(data: ResetPasswordModel, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    user.hashed_password = pwd_context.hash(data.new_password)
    db.add(user)
    db.commit()
    return {"msg": "Password reset successfully"}


@app.post('/v1/auth/refresh-token')
def refresh_token(user=Depends(manager)):
    access_token = manager.create_access_token(data={'sub': user.email})
    return {'access_token': access_token, 'token_type': 'bearer'}

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)
