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


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


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



# This /token endpoint handles the login flow for user authentication. Here is what it is doing:

# • It accepts a POST request with the user's login credentials (username and password) using the OAuth2PasswordRequestForm model provided by FastAPI OAuth2.

# • It tries to retrieve the user data from the fake_users_db database using the posted username as the key. 

# • If no user is found, it raises a 400 error saying incorrect credentials.

# • If a user is found, it gets the stored hashed password for that user from the DB.

# • It hashes the posted password using the fake_hash_password function and compares it to the hashed password from the DB.

# • If the hashed passwords do not match, it raises a 400 validation error saying the credentials are invalid.

# • Finally, if credentials are valid, it generates and returns a new access token containing the username. This acts as their authentication token.


# So in summary, it takes in the login credentials, verifies them against the users DB, and returns a fresh access token that can be used for authentication in subsequent requests.
# Let me know if any part of this login flow is unclear!



# You're right, let me explain the login flow more clearly with an example:
# How the Login Flow Works

# • User tries to login by sending username and password:

# POST /token
# {
#  "username": "johndoe",
#  "password": "super_secret_password" 
# }

# • The /token login endpoint receives this request 

# • It gets the user data from the database for the username "johndoe":


# user_dict = {
#   "username": "johndoe",
#   "hashed_password": "fakehashedsuper_secret_password",
#   ...
# } 

# • It hashes the sent password "super_secret_password" using the fake_hash_password function:

# hashed_password = "fakehashedsuper_secret_password" 

# • It compares this hashed password to the one stored for user "johndoe". They match, so login succeeds!

# • It generates a new access token containing the username, and returns this token:


# {
#  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huZG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
#  "token_type": "bearer"
# }
# This access token can now be used to authenticate for other requests.
# Let me know if the flow makes sense! I'm happy to explain any part in more detail.



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
