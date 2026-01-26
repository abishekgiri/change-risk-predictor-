from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from compliancebot.saas.config import SaaSConfig

engine = create_engine(SaaSConfig.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
