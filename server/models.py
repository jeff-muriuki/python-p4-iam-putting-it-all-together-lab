from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id= db.Column(db.Integer, primary_key = True)
    username= db.Column(db.String, nullable=False, unique=True)
    _password_hash= db.Column(db.String)
    image_url = db.Column(db.String)
    bio= db.Column(db.String)

    recipes= db.relationship('Recipe', back_populates='user', lazy=True)

    @hybrid_property
    def password_hash(self):
        raise AttributeError('password hashes may not be viewed.')
    
    @password_hash.setter
    def password_hash(self, password):
        password_hash= bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash= password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))
    
    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError('username must...')
        existing_username= User.query.filter_by(username=username).first()
        if existing_username:
            raise ValueError('username must...')
        return username
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'image_url': self.image_url,
            'bio': self.bio
            
        }
    

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id= db.Column(db.Integer, primary_key=True)
    title= db.Column(db.String, nullable=False)
    instructions= db.Column(db.String)
    minutes_to_complete= db.Column(db.Integer)

    user_id= db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='recipes')


    @validates('title')
    def validates_title(self, key, title):
        if not title:
            raise ValueError('title must...')
        return title

    @validates('instructions')
    def validates_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError('instructions must...')
        return instructions
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'instructions': self.instructions,
            'minutes_to_complete': self.minutes_to_complete,
            'user': self.user.to_dict()
        }