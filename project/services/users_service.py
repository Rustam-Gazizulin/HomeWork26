from typing import Optional

from project.dao import UsersDAO
from project.exceptions import ItemNotFound
from project.models import User
from project.tools.security import generate_password_hash


class UsersService:
    def __init__(self, dao: UsersDAO) -> None:
        self.dao = dao


    def get_item(self, pk: int) -> User:
        if user := self.dao.get_by_id(pk):
            return user
        raise ItemNotFound(f'User with pk={pk} not exists.')


    def get_all(self, page: Optional[int] = None) -> list[User]:
        return self.dao.get_all(page=page)


    def create_user(self, login, password):
        self.dao.create(login, password)


    def check(self, login, password):
        result = self.dao.get_user_by_login(login)
        if len(result):
            if result.get('password') == generate_password_hash(password):


