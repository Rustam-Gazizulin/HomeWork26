from flask_restx import Namespace, Resource
from flask import request
from project.setup.api.models import user
from project.container import user_service

api = Namespace('user')

@api.route('/')
class RegisterView(Resource):
    @api.marshal_with(user, as_list=True, code=200, description='OK')
    def get(self):
        data = request.json
        header = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Bearer', '')

        return user_service.get_user_by_token(data=data, refresh_token=header)


    @api.marshal_with(user, as_list=True, code=200, description='OK')
    def patch(self):
        data = request.json
        header = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Bearer', '')

        return user_service.update_user(data=data, refresh_token=header)


@api.route('/password/')
class LoginView(Resource):
    def put(self):
        data = request.json
        header = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Bearer', '')

        return user_service.update_password(data=data, refresh_token=header)

