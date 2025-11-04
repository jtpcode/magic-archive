from sqlite3 import DatabaseError
import bcrypt
from utils.database.database_connection import get_database_connection
from entities.user import User


class DatabaseFindAllError(Exception):
    pass


class DatabaseFindByUsernameError(Exception):
    pass


class DatabaseCreateError(Exception):
    pass


class UserRepository:
    """Class responsible for user database actions.

    Attributes:
        connection:
            Connection -object for the database connection.
    """

    def __init__(self, connection):
        """Class constructor. Creates a new user repository.

        Args:
            connection:
                Connection -object for the database connection.
        """

        self._connection = connection

    def _hash_password(self, password):
        """Hash password using bcrypt.

        Args:
            password (str): Plain text password

        Returns:
            str: Hashed password
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    def verify_password(self, password, hashed_password):
        """Verify password against hash.

        Args:
            password (str): Plain text password
            hashed_password (str): Hashed password from database

        Returns:
            bool: True if password matches
        """
        return bcrypt.checkpw(
            password.encode("utf-8"), hashed_password.encode("utf-8")
        )

    def find_all(self):
        """Returns all users.

        Returns:
            A list of User -objects or None.
        Raises:
            DatabaseFindAllError:
        """

        cursor = self._connection.cursor()

        try:
            cursor.execute("SELECT * FROM Users")
        except DatabaseError as e:
            raise DatabaseFindAllError(
                "Database error in User repository 'find_all'"
            ) from e

        rows = cursor.fetchall()

        if rows:
            return [User(row[1], row[2], row[0]) for row in rows]

        return None

    def find_by_username(self, username):
        """Returns a specific user.

        Args:
            username (str):
        Returns:
            A User -object or None if not found.
        Raises:
            DatabaseFindByUsernameError:
        """

        cursor = self._connection.cursor()

        try:
            cursor.execute(
                "SELECT * FROM Users WHERE username = ?",
                (username,)
            )
        except DatabaseError as e:
            raise DatabaseFindByUsernameError(
                "Database error in User repository 'find_by_username'"
            ) from e

        row = cursor.fetchone()

        if row:
            return User(row[1], row[2], row[0])

        return None

    def create(self, user):
        """Save new user into database.

        Args:
            user:
                User -object
        Returns:
            Id (primary key) of the user in database.
        Raises:
            DatabaseCreateError:
        """

        cursor = self._connection.cursor()

        hashed_password = self._hash_password(user.password)

        try:
            cursor.execute(
                "INSERT INTO Users (username, password) VALUES (?, ?)",
                (user.username, hashed_password)
            )
        except DatabaseError as e:
            raise DatabaseCreateError(
                "Database error in User repository 'create'"
            ) from e

        self._connection.commit()

        return cursor.lastrowid


user_repository = UserRepository(get_database_connection())
