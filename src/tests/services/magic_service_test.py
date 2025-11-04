import unittest
from unittest.mock import Mock, patch
from utils.database.initialize_database import initialize_database
from utils import test_utils
from repositories.user_repository import user_repository
from repositories.card_repository import card_repository
from entities.user import User

from services.magic_service import (
    MagicService,
    InvalidUsernameError,
    InvalidPasswordError,
    UsernameExistsError,
    UsernameTooShortError,
    PasswordTooShortError,
    CardExistsError,
    CardNotFoundError
)


class TestMagicService(unittest.TestCase):
    def setUp(self):
        initialize_database()
        self.user_alfa = User('alfa', '1234alfa5678')
        self.user_id = user_repository.create(self.user_alfa)

        self.fake_card = test_utils.create_fake_magic_card()
        self.card_id = card_repository.create(self.fake_card)

        self.mock_response = Mock()
        self.user_repository_mock = Mock()
        self.card_repository_mock = Mock()
        self.magic_service = MagicService(
            user_repository=self.user_repository_mock,
            card_repository=self.card_repository_mock
        )

    def login_user(self):
        self.user_repository_mock.find_by_username.return_value = self.user_alfa
        self.user_repository_mock.verify_password.return_value = True

        user = self.magic_service.login(
            self.user_alfa.username,
            self.user_alfa.password
        )

        return user

    def test_create_user_with_non_existing_username_and_valid_password(self):
        self.user_repository_mock.find_by_username.return_value = None
        self.user_repository_mock.create.return_value = self.user_alfa

        user = self.magic_service.create_user('alfa', '1234alfa5678')

        self.assertEqual(user.username, 'alfa')

    def test_create_user_with_existing_username(self):
        self.user_repository_mock.find_by_username.return_value = self.user_alfa

        self.assertRaises(
            UsernameExistsError,
            lambda: self.magic_service.create_user('alfa', '1234alfa5678')
        )

    def test_create_user_with_too_short_username(self):
        self.assertRaises(
            UsernameTooShortError,
            lambda: self.magic_service.create_user('al', '1234alfa5678')
        )

    def test_create_user_with_too_short_password(self):
        self.assertRaises(
            PasswordTooShortError,
            lambda: self.magic_service.create_user('alfa', '1234')
        )

    def test_get_current_user_success(self):
        self.user_repository_mock.find_by_username.return_value = self.user_alfa
        logged_user = self.magic_service.login(
            self.user_alfa.username, self.user_alfa.password
        )

        current_user = self.magic_service.get_current_user()

        self.assertEqual(current_user, logged_user)

    def test_login_with_valid_credentials(self):
        user = self.login_user()

        self.assertEqual(user.username, self.user_alfa.username)

    def test_login_with_invalid_username(self):
        self.user_repository_mock.find_by_username.return_value = None

        self.assertRaises(
            InvalidUsernameError,
            lambda: self.magic_service.login('foo', 'barbarbarbar')
        )

    def test_login_with_invalid_password(self):
        self.user_repository_mock.find_by_username.return_value = self.user_alfa
        self.user_repository_mock.verify_password.return_value = False

        self.assertRaises(
            InvalidPasswordError,
            lambda: self.magic_service.login('alfa', 'invalid_password')
        )

    def test_get_image_filenames_success(self):
        self.card_repository_mock.get_user_card_names_and_set_codes.return_value = [
            ("Test Card", "FAKE")
        ]
        result = self.magic_service.get_user_card_image_filenames(
            self.user_id
        )

        self.assertEqual(result, ["test_card_FAKE.png"])

    @patch("services.magic_service.Card.from_scryfall_json")
    @patch.object(MagicService, "_assign_card_to_user")
    def test_fetch_card_success(self, mock_assign_card, mock_from_scryfall_json):
        self.login_user()

        self.card_repository_mock.fetch_card_by_name_and_set.return_value = {
            "name": "Fake Card"
        }
        self.card_repository_mock.find_card_by_name_and_set.return_value = None
        mock_from_scryfall_json.return_value = self.fake_card
        self.card_repository_mock.create.return_value = 1

        self.magic_service.fetch_card("Fake Card", "FAKE_SET")

        mock_assign_card.assert_called_once_with(self.user_alfa.user_id, 1)

    def test_fetch_card_fails_on_card_exists(self):
        self.login_user()

        self.card_repository_mock.fetch_card_by_name_and_set.return_value = {
            "name": "Fake Card"
        }
        self.card_repository_mock.find_card_by_name_and_set.return_value = self.fake_card
        self.card_repository_mock.user_has_card.return_value = True

        self.assertRaises(
            CardExistsError,
            lambda: self.magic_service.fetch_card(
                "Fake Card", "FAKE_SET_CODE"
            )
        )

    @patch.object(MagicService, "_get_card")
    def test_delete_usercard_success(self, mock_get_card):
        self.login_user()

        mock_get_card.return_value = (
            {"name": "Fake Card"},
            self.fake_card
        )
        self.card_repository_mock.user_has_card.return_value = True

        self.magic_service.delete_usercard("Fake Card", "FAKE_SET_CODE")

        self.card_repository_mock.delete_card_from_user.assert_called_once_with(
            self.fake_card.card_id,
            self.user_alfa.user_id
        )

    @patch.object(MagicService, "_get_card")
    def test_delete_usercard_fails_on_card_not_in_collection(self, mock_get_card):
        self.login_user()

        mock_get_card.return_value = (
            {"name": "Fake Card"},
            None
        )
        self.card_repository_mock.user_has_card.return_value = False

        self.assertRaises(
            CardNotFoundError,
            lambda: self.magic_service.delete_usercard(
                "Fake Card",
                "FAKE_SET_CODE"
            )
        )

    def test_logout_user_successfully(self):
        self.user_repository_mock.find_by_username.return_value = self.user_alfa

        self.magic_service.login(
            self.user_alfa.username,
            self.user_alfa.password
        )
        self.magic_service.logout()

        self.assertEqual(self.magic_service.get_current_user(), None)
