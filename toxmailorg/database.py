from sqlalchemy import MetaData, Column, Integer, String
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


DEFAULT_DB = 'sqlite:////tmp/toxmailorg.db'
metadata = MetaData()
Base = declarative_base()
Session = sessionmaker()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    domain = Column(String)
    password = Column(String)
    toxid = Column(String)

    def __init__(self, name, password, toxid, domain='toxmail.org'):
        self.name = name
        self.password = password
        self.domain = domain
        self.toxid = toxid


class Domain(Base):
    __tablename__ = 'domains'

    id = Column(Integer, primary_key=True)
    name = Column(String)

    def __init__(self, name):
        self.name = name


_engines = {}


def get_session(sqluri=DEFAULT_DB):
    if sqluri not in _engines:
        _engines[sqluri] = create_engine(sqluri, echo=True)

    engine = _engines[sqluri]
    Base.metadata.create_all(engine, checkfirst=True)
    Session.configure(bind=engine)

    return Session()


if __name__ == '__main__':
    # prefill for testing
    session = get_session()

    toxid = ('DDDA71FD0310368991C34337107D3F0A5130'
             'F3E4CFF876B6B7F779F9212E4F79E3B759DA6593')

    tarek = User('tarek', 'secret', toxid, 'toxmail.org')
    domain = Domain('toxmail.org')

    session.add(tarek)
    session.add(domain)

    session.commit()
