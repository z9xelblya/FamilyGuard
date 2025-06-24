from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base


database_url = 'sqlite:///database.db'
engine = create_engine(database_url)
Session = sessionmaker(bind=engine)
Base = declarative_base()

async def init_db():
    Base.metadata.create_all(engine)

async def get_db():
    session = Session()
    try:
        yield session
    finally: session.close()
