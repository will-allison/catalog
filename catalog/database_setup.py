import os
import sys
from sqlalchemy.sql import func
from sqlalchemy import Column, ForeignKey, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=False)
	email = Column(String(250), nullable=False)
	picture = Column(String(250))

	@property
	def serialize(self):

		return {
			'name': self.name,
			'id': self.id,
			'email': self.email,
			'picture': self.picture
		}

class Category(Base):
	__tablename__ = 'category'

	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):

		return {
			'name': self.name,
			'id': self.id,
		}


class CategoryItem(Base):
	__tablename__ = 'category_item'

	title = Column(String(80), nullable=False)
	id = Column(Integer, primary_key=True)
	description = Column(String(5000), nullable=False)
	category_id = Column(Integer, ForeignKey('category.id'))
	category = relationship(Category)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)
	created_time = Column(DateTime(timezone=True), default=func.now())

# We added this serialize function to be able to send JSON objects in a
# serializable format
	@property
	def serialize(self):

		return {
			'title': self.title,
			'description': self.description,
			'id': self.id,
		}


engine = create_engine('sqlite:///catalog.db')


Base.metadata.create_all(engine)