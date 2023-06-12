## Project Description

Tests for a Django/SQLAlchemy Authentication API project.
The tests aim to validate system functionalities including system ping and version validation, handbook management, user authentication, user viewing, handling of exchange rates, password setting and updating, validation of input data. These tests include both positive scenarios (where operation is as expected) and negative scenarios (where operation deviates from the norm).

The testing suite utilizes both standard and parameterized tests as well as mock testing. Standard tests were used in cases where we have a set input and output data, such as validating API endpoints (`ping`, `version`, `handbooks`, etc.), while mock testing was used where the isolation of certain elements from external dependencies was required (like the models testing, where the tests were focused on the functionality of the model methods themselves, without involving the external password hashing or verification functionalities).

Below is a brief summary of the main areas covered by the tests:

### API Testing (`test_api.py`)
This script tests API endpoints like `ping`, `version`, `handbooks`, `auth`, `users`, and `services`. It validates the response from these endpoints, verifies the existence of handbooks, checks authentication with both valid and invalid credentials, inspects user data and tests the storage of exchange rates.

In addition to the API endpoint, the script also checks the integration with the database. It tests the correct creation of models in the database, ensuring that data is stored and managed correctly, thus implementing integrative tests approach.

### Model Testing (`test_models.py`)
This script tests the methods of the user models, including password setting, changing, checking and validation of names and social network IDs.

### Database Testing (`conftest.py`)
This script is responsible for setting up and tearing down the database for test purposes. It creates a test database and then drops it after the tests are done.

### Factories (`factories.py`)
This script describes the factories that create the test objects.


## Running the Tests

To run the tests, follow the instructions below:
    
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements-dev.txt
    pytest tests
    
The tests can be run in parallel using the pytest-xdist plugin. To run the tests in parallel execute:
    pytest -n INT
    
Where INT is the number of CPU available. Use "auto" for automatic determination.

