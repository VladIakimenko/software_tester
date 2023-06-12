import uuid

import pytest
from unittest.mock import patch, MagicMock, call
from api.models import AbstractUser, SuperAdmin, Operator, InvalidParamValueError

from tests.factories import *


@patch('api.models.validate_password')
def test_set_password(mock_validate_password):
    user = AbstractUser()
    user.set_password('StrongPassword12345')
    
    mock_validate_password.assert_called_with('StrongPassword12345', user=user)


def test_change_password():
    user = AbstractUser()
    user.password_hash = 'hash12345'
    
    with (
        patch.object(AbstractUser, 'check_password', return_value=True), 
        patch.object(AbstractUser, 'set_password') as mock_set_password
    ):
        user.change_password('password_old', 'password_new')

    mock_set_password.assert_called_with('password_new')


def test_check_password():
    user = AbstractUser()
    user.password_hash = 'hash12345'

    mock_set_password = MagicMock()
    user.set_password = mock_set_password
    
    def mock_check_password(raw_password, password_hash, setter):
        setter(raw_password)
        if raw_password == 'StrongPassword12345':
            return False
        else:
            return True
    
    with patch('api.models.check_password', new=mock_check_password):
        result_mismatch = user.check_password('wrong_password')
        result_match = user.check_password('StrongPassword12345')
    
    expected_call = call('wrong_password')
    assert expected_call in mock_set_password.call_args_list


def test_validate_name_valid_email():
    user = AbstractUser()
    email = "test@example.com"
    result = user.validate_name("email", email)
    assert result == email


def test_validate_name_invalid_email():
    user = AbstractUser()
    email = "invalid_email"
    with pytest.raises(InvalidParamValueError):
        user.validate_name("email", email)


def test_validate_social_network_id_valid_length():
    user = AbstractUser()
    social_id = "1234567890" * 15
    result = user.validate_social_network_id("facebook_id", social_id)
    assert result == social_id
    

def test_validate_social_network_id_invalid_length():
    user = AbstractUser()
    social_id = "1234567890" * 16
    with pytest.raises(InvalidParamValueError):
        user.validate_social_network_id("facebook_id", social_id)