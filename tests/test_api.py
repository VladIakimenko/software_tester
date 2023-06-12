import jwt
import datetime
import os

import random

import pytest
from django.urls import reverse
from django.conf import settings

from tests.factories import *
from api.models import handbook_map, AbstractUser, ExchangeRatesRecord


USER_TYPES = [user for user in handbook_map['user_types'] if user != 'USER']


def get_token(user_id):
    return jwt.encode(
    {'user_id': str(user_id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
    os.environ.get('APP_JWT_SECRET_KEY'),
    algorithm='HS256'
    )


# ping    Endpoint: re_path(r"^ping/?$", PingView, name="ping")
def test_ping(client):
    response = client.get(reverse("api:ping"), content_type="application/json")
    assert response.status_code == 200
    assert response.json() == {"response": "pong"}


# versions    Endpoint: re_path(r"^version/?$", AppVersionView, name="app_versions")
def test_versions(client):
    response = client.get(reverse("api:app_versions"), content_type="application/json")
    assert response.status_code == 200
    assert sorted(settings.INSTALLED_APPS) == sorted(list(response.json().keys()))
    

# handbooks
    # Endpoint: re_path(r"^handbooks/?$", HandbooksListView, name="handbooks_list")
def test_get_handbooks(client, db):
    url = reverse('api:handbooks_list')
    response = client.get(url)
    assert response.status_code == 200
    assert set(response.json()) == set(handbook_map.keys())


    # Endpoint: re_path(r"^handbooks/(?P<handbook_name>\w+)/?$", HandbookView, name="handbooks_item_list")
@pytest.mark.parametrize("name, enum", handbook_map.items())
def test_get_existing_handbook(client, db, name, enum):
    url = reverse('api:handbooks_item_list', kwargs={'handbook_name': name})
    response = client.get(url)
    assert response.status_code == 200
    if isinstance(response.json()[0], str):
        assert set(enum.__members__.keys()) == set(response.json())
    else:
        assert set(enum.__members__.keys()) == set(handbook['name'] for handbook in response.json())

def test_get_non_existent_handbook(client):
    url = reverse('api:handbooks_item_list', kwargs={'handbook_name': 'legjournal'})
    response = client.get(url)
    assert response.status_code == 404
    

# auth  Endpoint: re_path(r"^auth/auth/?$", AuthRegisterView, name="auth")
def test_auth_bad_creds(client, db):
    response = client.post(
        reverse("api:auth"),
        content_type="application/json",
        data={
            "engine": "email",
            "credentials": {
                "email": "some@email",
                "password": "StrongPassword",
            },
        },
    )
    assert response.status_code == 401


# auth    Endpoint:     re_path(r"^auth/auth/?$", AuthRegisterView, name="auth"),
@pytest.mark.parametrize("user_type", USER_TYPES)
def test_auth_valid_creds(client, db, user_type):
    FactoryType = choose_user_factory(user_type)
    user = FactoryType.create()
    user.set_password("StrongPassword12345")
    db.add(user)
    db.commit()

    response = client.post(
        reverse("api:auth"),
        content_type="application/json",
        data={
            "engine": "email",
            "credentials": {
                "email": user.email,
                "password": "StrongPassword12345",
            }
        },
    )
    assert response.status_code == 200
    user_from_db = db.query(AbstractUser).filter_by(email=user.email).first()
    assert user_from_db is not None
    assert user_from_db.email == user.email
    assert user_from_db.first_name == user.first_name
    assert user_from_db.last_name == user.last_name
    assert user_from_db.user_type == user_type
    assert response.json()['access_token']




# users    Endpoint: re_path(r"^users/(?P<user_id>[\w-]+)/?$", UserView, name="user")
@pytest.mark.parametrize("user_type", USER_TYPES)
def test_user_view(client, db, user_type):
    UserFactory = choose_user_factory(user_type)
    user_self = UserFactory.create()
    user_self.set_password("StrongPassword12345")
    db.add(user_self)
    db.commit()

    UserFactory = choose_user_factory(random.choice(user_type))
    user_other = UserFactory.create()

    auth_response = client.post(
        reverse("api:auth"),
        content_type="application/json",
        data={
            "engine": "email",
            "credentials": {
                "email": user_self.email,
                "password": "StrongPassword12345",
            }
        },
    )

    token = get_token(user_self.user_id)

    response = client.get(reverse("api:user", args=[user_self.user_id]), **{'HTTP_X_LAMB_AUTH_TOKEN': token})
    assert response.status_code == 200
    assert response.json()['user_id'] == str(user_self.user_id)

    response = client.get(reverse("api:user", args=[user_other.user_id]), **{'HTTP_X_LAMB_AUTH_TOKEN': token})

    if user_type == 'SUPER_ADMIN':
        assert response.status_code == 200
        assert response.json()['user_id'] == str(user_other.user_id)
    else:
        assert response.status_code == 403
    

# services    re_path(r"^services/store-rates/?$", StoreExchangeRatesView, name="store_exchanges_rates")
def test_store_exchange_rates_view(client, db):
    UserFactory = choose_user_factory('OPERATOR')
    operator = UserFactory.create()
    operator.set_password("StrongPassword12345")
    db.add(operator)
    db.commit()

    auth_response = client.post(
        reverse("api:auth"),
        content_type="application/json",
        data={
            "engine": "email",
            "credentials": {
                "email": operator.email,
                "password": "StrongPassword12345",
            }
        },
    )

    token = get_token(operator.user_id)

    response_positive = client.post(
        reverse("api:store_exchanges_rates"),
        content_type="application/json",
        **{'HTTP_X_LAMB_AUTH_TOKEN': token}
    )

    response_negative = client.post(
        reverse("api:store_exchanges_rates"),
        content_type="application/json"
    )

    assert response_positive.status_code == 201
    assert response_negative.json().get('error_message') == (
    'User auth token is not valid. You must be logged for this request.'
    )
