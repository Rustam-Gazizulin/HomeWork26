from flask_restx import Namespace, Resource
from flask import request
from project.setup.api.models import user
from project.container import user_service

api = Namespace('auth')

@api.route('/register/')


