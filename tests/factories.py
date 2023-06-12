import logging
import factory

# Project
from api.models import *

__all__ = ["AlchemyModelFactory", "choose_user_factory"]

logger = logging.getLogger(__name__)


def get_or_create(sub_factory):
    """
    Returns first instance of a given factory, create if not exist.
    """

    session = AlchemyModelFactory._meta.sqlalchemy_session
    instance = session.query(sub_factory._meta.model).first()
    if not instance:
        instance = sub_factory()
    return instance


class AlchemyModelFactory(factory.alchemy.SQLAlchemyModelFactory):
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Save an instance of the model, using shared DB session."""
        cls._meta.sqlalchemy_session = AlchemyModelFactory._meta.sqlalchemy_session
        cls._meta.sqlalchemy_session_persistence = "commit"
        return super()._create(model_class, *args, **kwargs)


class AbstractUserFactory(AlchemyModelFactory):
    email = factory.Faker("email")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")    
    is_email_confirmed = True
    is_confirmed = True
    is_blocked = False


class SuperAdminFactory(AbstractUserFactory):
    
    class Meta:
        model = SuperAdmin


class OperatorFactory(AbstractUserFactory):

    class Meta:
        model = Operator


def choose_user_factory(identity):
    return(SuperAdminFactory, OperatorFactory)[identity == "OPERATOR"]

    
