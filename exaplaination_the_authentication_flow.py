from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()


def fake_hash_password(password: str):
    return "fakehashed" + password

# Sure, I'm happy to provide more focused explanations on specific parts of the code! Providing context incrementally this way allows me to give clearer and simpler answers.
# As for the fake_hash_password function:
# The purpose of this function is to simulate / fake the generation of a hashed password, since this example app uses a fake in-memory user database. 
# What it does is:

# • It takes in the plain text password as input

# • It appends the string "fakehashed" to the beginning of the password 

# • And returns the resulting string


# For example:
# password = "1234pass"

# fake_hashed = fake_hash_password(password) 

# print(fake_hashed)

# # Prints: fakehashed1234pass
# So essentially, it pretends to "hash" the password by just prefixing a string to it. 
# This allows comparing the hashed value with the one stored in the fake DB per user without having to implement real password hashing.
# Let me know if this helps explain what this short and simple function is doing!


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


# The get_user function is used to retrieve a user object from the fake database based on the username. Here is what it does step-by-step:

# • It accepts two arguments:

# • db - This is the fake database dictionary that maps usernames to user dictionaries
# • username - The username of the user we want to fetch


# • It checks if that username exists in the db:
# if username in db:

# • If yes, it gets the user dictionary associated with that username: 
# user_dict = db[username]

# • It then converts the user dictionary into a Pydantic UserInDB object:
# return UserInDB(**user_dict)

# • This uses the ** unpacking we discussed earlier to populate the UserInDB model with data from the user_dict.


# So in summary, it:

# • Checks if user exists 
# • Gets raw user data dict from fake DB
# • Converts into nice UserInDB object
# • Returns the UserInDB object

# This allows other parts of the code to work with a cleaner UserInDB instance rather than the raw dict.
# Let me know if this helps explain what get_user is doing!

# Here is an example walkthrough of how the get_user function retrieves a user from the fake database:
# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe", 
#         "email": "johndoe@example.com",
#         #... other fields
#     },
#     "janedoe": {
#         "username": "janedoe",
#         "email": "janedoe@example.com",
#        # ... other fields
#     }
# }

# username_to_fetch = "johndoe"

# user_in_db = get_user(fake_users_db, username_to_fetch)

# print(user_in_db)
# # UserInDB(username='johndoe', email='johndoe@example.com', ...) 

# print(user_in_db.username)
# # johndoe

# print(user_in_db.email)  
# # johndoe@example.com
# So with get_user:

# • We passed the fake DB and wanted username 
# • It returned a UserInDB instance for that user
# • We can access the user attributes easily

# The key thing is it abstracts away the underlying DB representation and gives back a clean Pydantic user object.
# Let me know if this example helps illustrate how get_user functions!





def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user

# You're right, let me explain the fake_decode_token() function first in a step-by-step manner and then illustrate with an example output:
# What the function does:

# • It accepts an access_token string as input. This token should contain the username in some encoded form. 

# • Its purpose is to decode the token and extract the username string from it. 

# • But since we are using simple username-only strings as tokens in this example app, it skips any decoding. 

# • It directly passes the input token string as the username to the get_user() function.

# • get_user() fetches the UserInDB object for that username from the fake database.

# • This UserInDB object representing the user identified by the token is returned by fake_decode_token().


# Example:  
# token = "johndoe"

# decoded_user = fake_decode_token(token)

# print(decoded_user)

# # Prints: 
# # UserInDB(username='johndoe', ...)
# Here, token contains the username johndoe. This gets passed directly to get_user(), which returns a UserInDB object for that user data.
# So in this way, it takes the token, extracts the username, and fetches the user details.
# Let me know if the step-by-step explanation followed by the output example helps illustrate the purpose and functioning of fake_decode_token()!

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# Got it, let me explain the get_current_user function clearly first and then show an example:
# What the function does

# • It accepts an access token string that is passed via the oauth2_scheme dependency. 

# • It calls the fake_decode_token() function we saw earlier, passing the token.

# • fake_decode_token() extracts the username from the token and returns a UserInDB object for that user.

# • We check if a valid UserInDB object was returned. 

# • If not, it means the token was invalid, so we raise an Unauthorized error.

# • Otherwise, we return the UserInDB object back to the caller.


# Example:
# token = "johndoe" 

# user = get_current_user(token)

# print(user)
# # UserInDB(username='johndoe', ...)
# Here's what happened:

# • We passed username "johndoe" as token 
# • fake_decode_token() extracted username and returned UserInDB object
# • Since valid object returned, user is set to that object 
# • UserInDB is returned

# So it decodes token to get user, or raises error if invalid.
# Let me know if this helps explain the flow!






async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# The get_current_active_user dependency builds on top of get_current_user to add an extra check that the user is active.
# It works as follows:

# • It depends on get_current_user, so it first gets the authenticated user object for the request

# • It then checks if the user is disabled:


# if current_user.disabled:
#     raise HTTPException(status_code=400, detail="Inactive user")

# • If disabled, it raises an exception stating the user is inactive

# • Otherwise, it simply returns the user object


# So in summary, it:

# • Leverages get_current_user to authenticate user and get User object
# • Adds additional check that user is not disabled
# • Raises exception if user is inactive
# • Returns user object if active

# This allows routes to depend on get_current_active_user instead of get_current_user to require that the authenticated user is active.
# For example:
# @app.get("/account")
# def get_account(user: User = Depends(get_current_active_user)):
#    # user is guaranteed to be active 
# So it encapsulates an extra "active user" check on top of authentication.
# Let me know if this helps explain the purpose and flow of get_current_active_user!









@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}
# Yes, you are absolutely right!
# The key purpose of this login endpoint is to:

# • Validate the username and password
# • On successful validation, return an access token for that user

# So once the username and password check passes:

# • It generates an access token. Here for simplicity, it just uses the username as the token.

# • In a real app, this would be a cryptographically signed JWT token.

# • It also mentions the token type, which is a standard auth protocol. bearer just means this token gets passed in the request header later to authenticate requests.


# So when the client (frontend, mobile app etc) makes a login request with correct credentials:

# • The endpoint checks if valid user
# • On success, returns a token 
# • Client stores this token and sends it along with future requests
# • Subsequent authorized endpoints verify the token to authenticate the user

# So yes, that return line with access_token is crucial  - it gives the client that requested login a token to make further authorized requests to access protected resources.
# Let me know if this helps explain the purpose of that return!

@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user



# The @app.get("/users/me") endpoint serves to return the details of the currently authenticated user.
# Let's understand it step-by-step:

# • It handles GET requests to the /users/me route

# • It has a dependency on get_current_active_user 

# • This is another function that retrieves the user based on the access token


# • The token was returned earlier on login and sent by client on this request

# • get_current_active_user verifies this token and returns the User object

# • This user object is then passed to our endpoint via the current_user parameter

# • Inside the endpoint, we simply return this current_user object back to the client


# In summary:

# • Client logged in previously to get a token 
# • Sends this token with a request to /users/me 
# • Server verifies token to extract user identity
# • Fetches user data from DB  
# • Returns user data to the client

# This allows displaying user profile, account settings etc because now the server knows the identity of the requesting user.
# Let me know if this helps explain the purpose of this endpoint!


#------------------------------------------------------------------------------------------------------
# #Here are some examples of using ** to unpack dictionaries into keyword arguments, with output:
# dict = {"name": "John", "age": 30}

# def print_user(name, age):
#     print(f"Name: {name}, Age: {age}")

# # Without **
# print_user(dict["name"], dict["age"])
# # Output: Name: John, Age: 30

# # With **  
# print_user(**dict) 
# # Output: Name: John, Age: 30
# As you can see, the output is the same, but using ** is cleaner.
# Another example with a class:
# class User:
#     def __init__(self, name, age):
#         print(f"Created user {name} with age {age}")

# user_dict = {"name": "Sarah", "age": 25}

# # Without **
# User(user_dict["name"], user_dict["age"])  
# # Output: Created user Sarah with age 25

# # With **
# User(**user_dict)   
# # Output: Created user Sarah with age 25
# And printing the user object:
# user = User(**user_dict)
# print(user)
# # Output: <__main__.User object at 0x7fc2d41a82e0> 
# The key thing is that ** passes the dict items as individual kwargs to the function/method. The output is therefore the same. But it avoids having to access the dict elements manually.
    



# Answer
# Here is an example to demonstrate how UserInDB(**user_dict) works in the context of the code you provided:
# user_dict = {
#     "username": "johndoe",
#     "full_name": "John Doe",
#     "email": "johndoe@example.com",
#     "hashed_password": "fakehashedsecret",
#     "disabled": False    
# }

# print(user_dict)
# # {'username': 'johndoe', 'full_name': 'John Doe', ...}

# user = UserInDB(**user_dict)

# print(user)
# # username='johndoe' full_name='John Doe' email='johndoe@example.com' hashed_password='fakehashedsecret' disabled=False

# print(user.username) 
# # johndoe

# print(user.hashed_password)
# # fakehashedsecret 
# Here's what happens step-by-step when doing UserInDB(**user_dict):

# • We start with a dictionary user_dict containing the user data

# • We unpack this dict using ** - this spreads the key-value pairs as kwargs

# • The kwargs match the initialization arguments of UserInDB 

# • username=..., full_name=..., etc


# • This constructs a UserInDB instance with the data from the dict

# • We can now access the user data as attributes on the user object


# So essentially, ** unpacks the dict into a format that can be used directly to construct the UserInDB object.
# Let me know if this helps explain what's happening!    