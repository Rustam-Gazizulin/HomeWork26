from typing import Optional

from project.dao import UsersDAO
from project.exceptions import ItemNotFound
from project.models import User
from project.tools.security import generate_tokens, approve_refresh_token


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


    def get_user_by_login(self, login):
        return self.dao.get_user_by_login(login)


    def check(self, login, password):
        user = self.get_user_by_login(login)
        return generate_tokens(email=user.email, password=password, password_hash=user.password)


    def update_token(self, refresh_token):
        return approve_refresh_token(refresh_token)

