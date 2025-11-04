from repositories.user_repository import (
    user_repository as default_user_repository
)
from repositories.card_repository import (
    card_repository as default_card_repository
)
from entities.user import User
from entities.card import Card
from utils.card_utils import card_name_to_png_filename


class InvalidUsernameError(Exception):
    pass


class InvalidPasswordError(Exception):
    pass


class UsernameExistsError(Exception):
    pass


class UsernameTooShortError(Exception):
    pass


class PasswordTooShortError(Exception):
    pass


class CardExistsError(Exception):
    pass


class CardNotFoundError(Exception):
    pass


class MagicService:
    """Class responsible for 'Magic archive' application logic.

    Attributes:
        user_repository:
            Repository responsible for user database actions.
        card_repository:
            Repository responsible for card operations: api.scryfall.com connection
            and database/disk actions.
    """

    def __init__(
        self,
        user_repository=default_user_repository,
        card_repository=default_card_repository
    ):
        """Class constructor. Creates a new service for the application logic.

        Args:
            user_repository:
                Repository responsible for user database actions.
            card_repository:
                Repository responsible for card operations: api.scryfall.com connection
                and database/disk actions.
        """

        self._user = None
        self._user_repository = user_repository
        self._card_repository = card_repository

    def create_user(self, username, password):
        """Creates a new user. First validates that username
        and password are valid.

        Args:
            username (str):
            password (str):
        Returns:
            User -object
        Raises:
            UsernameTooShortError:
                Username is too short (minimum 3 characters).
            PasswordTooShortError:
                Password is too short (minimum 12 characters).
            UsernameExistsError:
                Username already exist.
        """

        if len(username) < 3:
            raise UsernameTooShortError(
                "Username must be at least 3 characters long"
            )
        if len(password) < 12:
            raise PasswordTooShortError(
                "Password must be at least 12 characters long"
            )
        if self._user_repository.find_by_username(username):
            raise UsernameExistsError(f"Username {username} exists already")

        user = self._user_repository.create(User(username, password))

        return user

    def get_current_user(self):
        """Returns current user who's logged in.

        Returns:
            User -object.
        """

        return self._user

    def login(self, username, password):
        """User login.

        Args:
            username (str):
            password (str):
        Returns:
            User -object
        Raises:
            InvalidUsernameError:
                Username doesn't match.
            InvalidPasswordError:
                Password doesn't match.
        """

        user = self._user_repository.find_by_username(username)

        if not user:
            raise InvalidUsernameError("Invalid username")

        if not self._user_repository.verify_password(password, user.password):
            raise InvalidPasswordError("Invalid password")

        self._user = user

        return user

    def get_user_card_image_filenames(self, user_id):
        """Gets the card image filenames of the current user.

        Args:
            user_id (int): User database id (primary key)

        Returns:
            List: List of image filenames for users cards.
        """

        results = self._card_repository.get_user_card_names_and_set_codes(
            user_id
        )

        if results:
            return [card_name_to_png_filename(res[0], res[1]) for res in results]
        return []

    def _assign_card_to_user(self, user_id, card_id):
        """Assigns card to current user in database.

        Args:
            user_id (int): User database id (primary key)
            card_id (int): Card database id (primary key)
        """

        self._card_repository.add_card_to_user(
            user_id,
            card_id
        )

    def _get_card(self, card_name, set_code):
        """Get card data from api.scryfall.com to get precise name
        of the card. Then check if card exists in database already.

        Args:
            card_name (card_name):
            set_code (set_code): The code of the card set.

        Returns:
            Card data in dict format and a Card -object if in database,
            else None.
        """
        card_data = self._card_repository.fetch_card_by_name_and_set(
            card_name,
            set_code
        )
        card_precise_name = card_data["name"]
        card = self._card_repository.find_card_by_name_and_set(
            card_precise_name,
            set_code
        )

        return card_data, card

    def fetch_card(self, card_name, set_code):
        """Fetches a new Magic card based on card name and set code.
        First fetches the card data from api.scryfall.com, because the api
        can handle different spellings for the card name, like exclude
        commas and apostrophies (ie. hunters talent = Hunter's Talent). 

        Then checks if the card already exists in local database and if so,
        checks if the current user has it already. Lastly the card and its image
        are saved if not in database and then assigned to current user.

        NOTE: For double sided cards ie. 'transform' and 'modal_dfc' the card
        image uris are located in database column 'card_faces', because those cards
        have info+image on both sides of the card.

        Args:
            card_name (str):
            set_code (str):
        Raises:
            CardExistsError:
                Card already exists in database.
        """

        card_data, card = self._get_card(card_name, set_code)

        if card:
            card_id = card.card_id
            if self._card_repository.user_has_card(self._user.user_id, card_id):
                raise CardExistsError(
                    f"Card '{card.name}' is already in collection"
                )
        else:
            card = Card.from_scryfall_json(card_data)
            card_id = self._card_repository.create(card)
            image_uris = card.image_uris
            if not image_uris:
                # HACK: For double sided cards we load only one side (face)
                first_face = card.card_faces[0]
                image_uris = first_face["image_uris"]
            self._card_repository.save_card_image(
                image_uris["small"],
                card.name,
                card.set_code
            )

        self._assign_card_to_user(self._user.user_id, card_id)

    def delete_usercard(self, card_name, set_code):
        """Deletes card from current user, but not from database.
        Deletion is based on card name and set.

        Args:
            card_name (str):
            set_code (str):
        Raises:
            CardNotFoundError:
        """

        card_data, card = self._get_card(card_name, set_code)

        if card and self._card_repository.user_has_card(
            self._user.user_id,
            card.card_id
        ):
            self._card_repository.delete_card_from_user(
                card.card_id,
                self._user.user_id
            )
        else:
            raise CardNotFoundError(
                f"Card '{card_data['name']}'not in collection"
            )

    def logout(self):
        """Logout current user."""

        self._user = None


magic_service = MagicService()
