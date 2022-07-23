from flask_restx import fields, Model

from project.setup.api import api

genre: Model = api.model('Жанр', {
    'id': fields.Integer(required=True, example=1),
    'name': fields.String(required=True, max_length=100, example='Комедия'),
})

director: Model = api.model('Режиссер', {
    'id': fields.Integer(required=True, example=1),
    'name': fields.String(required=True, max_length=100, example='Тарантино'),
})

movie: Model = api.model('Фильм', {
    'id': fields.Integer(required=True, example=1),
    'title': fields.String(required=True, max_length=100, example='От заката до рассвета'),
    'description': fields.String(required=True, max_length=250, example='Про преступников и вампиров'),
    'trailer': fields.String(required=True, max_length=100, example='https://www.yutube.com'),
    'year': fields.Integer(required=True, example='2012'),
    'rating': fields.Float(required=True, example=8.0),
    'genre': fields.Nested(genre),
    'director': fields.Nested(director),
})

user: Model = api.model('Пользователь', {
    'id': fields.Integer(required=True, example=1),
    'email': fields.String(required=True, max_length=100, example='3310091@mail.ru'),
    'password': fields.String(required=True, max_length=100, example='12345'),
    'name': fields.String(required=True, max_length=100, example='Alex'),
    'surname': fields.String(required=True, max_length=100, example='Yakovlev'),
    'genre': fields.Nested(genre),
})
