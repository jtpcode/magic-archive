# Changelog

## Week 3

- User can see the "login" and "create user" views
- Added local SQLite database access
- Added UserRepository class for handling User database actions
- Added MagicService class for handling application logic
- Added tasks for quick CLI start and testing
- 'Create user' -button creates a new user into the database
- UserRepository tested for "create new user" and "find all users"

## Week 4

- User can login and logout
- Error message is shown if login credentials are not correct
- Error message is shown if username already exists when creating a new account
- Successfull account creation directs user to "login" view
- Successfull login directs user to "card management" view
- User can see the "card management" view
- Logout directs user to "login" view
- UserRepository tested for "find by username"
- MagicService tested for "login" and "create user"

## Week 5

- Separate database environment for testing created
- Hide password characters in UI
- Add notification of successfull user creation
- Move helper functions/files to 'utils' directory
- Add CardRepository for fetching cards from api.scryfall.com and storing them in Sqlite
- Initial version of "Magic card view" for fetching and showing Magic cards
- Fetching cards from api.scryfall.com works, currently only prints the name in terminal
- CardRepository tested for "fetch_card_by_name_and_set"

## Week 6
- Update docstrings
- New card is now saved into database
- Card view is partially working, doesn't yet dynamically update when card is added
- CardRepository tested for "fetch_all_sets", "find_by_card_name" and "create"
- Improved error handling in fetching cards from scryfall.com

## Week 7
- Card view dynamic update after adding/removing a card
- Card view react correctly to window resize
- Only show cards owned by current user
- CardRepository tested for "save_card_image", "add_card_to_user", "get_user_card_names", "user_has_card", "delete_card_from_user"
- MagicService tested for "get_current_user", "fetch_card", "get_image_filenames", "delete_usercard"
- Add more notifications (errors etc.) for user when adding/removing cards
- Special cards (ie. double sided and flip cards) handled
- Added "delete card from user" and error handling.
- Change button: Submit -> Add

  ## 4.11.2025
  - Add hashing of user passwords when saving into database
  - Alter login accordingly
  - Alter tests accordingly
