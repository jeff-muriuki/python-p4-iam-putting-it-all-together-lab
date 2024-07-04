#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        # Validate the user input
        if not username or not password:
            return {'error': 'Username and password are required.'}, 422
        
        try:
            # Example of creating a new user in the database
            new_user = User(username=username, image_url=image_url, bio=bio)
            new_user.password_hash=password
            db.session.add(new_user)
            db.session.commit()

            # Set user_id in session
            session['user_id'] = new_user.id

            # Prepare response
            response_data = {
                'user_id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }

            return response_data, 201
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists.'}, 422

class CheckSession(Resource):
    def get(self):
        try:
            if 'user_id' in session:
                user_id = session['user_id']
                user = db.session.query(User).filter_by(id=user_id).first()

                if user:
                    response_data = {
                        'id': user.id,  # Ensure the response uses 'id'
                        'username': user.username,
                        'image_url': user.image_url,
                        'bio': user.bio
                    }
                    return response_data, 200
                else:
                    return {'error': 'User not found.'}, 401
            else:
                return {'error': 'User not logged in.'}, 401
        except Exception as e:
            return {'error': str(e)}, 500

class Login(Resource):
    def post(self):
        username= request.get_json()['username']
        password= request.get_json()['password']
        user= User.query.filter(User.username==username).first()

        if user and user.authenticate(password):
            session['user_id']= user.id
            response= {
                'id': user.id,
                'username': user.username,
                'image_ur': user.image_url,
                'bio': user.bio
            }
            return response, 200
        else:
            return {}, 401
        

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id', None)
            return {}, 401 #test wanted 401 but should be 204 I guess. Not sure
        else:    
            return {}, 401
class RecipeIndex(Resource):
    def get(self):
        if  session['user_id']:

            user_id = session['user_id']
            recipes = Recipe.query.filter_by(user_id=user_id).all()
            recipes_list = [recipe.to_dict() for recipe in recipes]
            return recipes_list, 200
        else:
            return {}, 401
        

    def post(self):
        if 'user_id'  in session:
            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            if not title:
                return {'message': 'Invalid data'}, 422
            if not instructions or len(instructions) < 50:
                return {'message': 'Invalid data'}, 422


            
            new_recipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=session['user_id']
                )

            db.session.add(new_recipe)
            db.session.commit()

            return new_recipe.to_dict(), 201
        
        else:
            return {}, 400
            
        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)