import sys
import datetime
import os
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    id = Column(Integer, primary_key=True)


class Categories(Base):
    __tablename__ = 'categories'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):

        return{
            'id': self.id,
            'name': self.name,
        }


class Items(Base):
    __tablename__ = 'items'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    date_created = Column(DateTime, default=datetime.datetime.utcnow)
    categories_id = Column(Integer, ForeignKey('categories.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    categories = relationship(Categories)

    @property
    def serialize(self):

        return{
            'id': self.id,
            'name': self.name,
            'description': self.description,
        }

engine = create_engine('sqlite:///sportsEquipmentwithusers.db')

Base.metadata.create_all(engine)
