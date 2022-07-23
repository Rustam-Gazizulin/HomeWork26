from project.dao.base import BaseDAO
from project.models import *


class GenresDAO(BaseDAO[Genre]):
    __model__ = Genre


class DirectorsDAO(BaseDAO[Director]):
    __model__ = Director


class MovieDAO(BaseDAO[Movie]):
    __model__ = Movie


class UserDAO(BaseDAO[User]):
    __model__ = User




