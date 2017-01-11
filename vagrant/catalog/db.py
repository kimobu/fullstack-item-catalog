import sys
from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import relationship

from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50))
    email = Column(String(50))
    account_type = Column(String(50))


class Category(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User, backref="categories")

    def to_json(self):
        return {'id': self.id, 'name': self.name}


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    description = Column(Text())
    category_id = Column(Integer, ForeignKey('categories.id'))
    category = relationship(Category, backref="items")
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User, backref="items")

    def to_json(self):
        return {'id': self.id, 'name': self.name,
                'description': self.description,
                'category_id': self.category_id,
                'category': self.category.name}


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
