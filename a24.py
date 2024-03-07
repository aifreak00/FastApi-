from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
#• pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto"): This creates a password context using bcrypt password hashing. Bcrypt is a secure password hashing algorithm that will be used to store user passwords securely in the database. The "deprecated" auto setting allows seamless upgrades to newer and more secure algorithms in the future.
#Yes, that's correct. The pwd_context = CryptContext(...) line initializes the hashing tool but doesn't actually hash anything yet. It just sets up the CryptContext to use bcrypt.
# The actual password hashing happens in the get_password_hash() function using the pwd_context.hash() method. 
# So the flow is:

# • pwd_context = CryptContext() - Initialize bcrypt password hashing tool

# • When we need to hash a password: 
# hashed = get_password_hash(plain_text_password) 
# Inside get_password_hash:
# return pwd_context.hash(plain_text_password) - Actually hash password using bcrypt


# So pwd_context is like an instance of the bcrypt hashing algorithm. The pwd_context.hash() call is what does the actual one-way encryption on the password.
# Good understanding! Initializing the tool then using it to hash passwords when needed.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
#This configures OAuth2 password authentication flow. It sets the endpoint for exchanging username/password for access tokens to "/token".
app = FastAPI()
# This creates a FastAPI application instance. All the API endpoints will be registered with this app.

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]   #value retriving db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Sure, let me explain the authenticate_user() function using some simple examples:
# The goal of this function is to verify a user's credentials - their username and password.
# It takes 3 arguments:
# fake_db: Our database of users 
# username: The username entered by the user trying to log in
# password: The password they entered 
# The steps:

# • Get the user data from the database:
# user = get_user(fake_db, username)
# Call the get_user function we discussed before to fetch the User object from fake_db matching the username.

# • If user not found, return False:
# if not user:
#     return False
# If get_user() did not find that username, return False indicating invalid login.

# • Verify password:
# verify_password(password, user.hashed_password)
# Take the entered password, and the hashed password from the user object, and verify they match.

# • If password wrong, return False:
# if not verify_password(): 
#     return False
# If verification failed, passwords did not match. Return False for failure.

# • If all checks passed, return the User object:
# return user


# So in summary, it takes a username and password, checks they are valid credentials by getting the user data and verifying against stored passwords.
# Let me know if this helps explain the user authentication flow!


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#create an token jwt and sign it

# This code is creating JSON Web Tokens (JWTs) to use as access tokens for authentication and authorization.
# Specifically, the create_access_token function is taking in:

# • data: a dictionary of data to encode into the JWT payload
# • expires_delta: an optional timedelta for when the token should expire

# It starts by making a copy of the data dictionary to encode so that it doesn't modify the original.
# Then it checks if an expiration timedelta was passed in. If so, it calculates the expiration date by adding that timedelta to the current UTC datetime. If no timedelta is passed, it defaults to expiring in 15 minutes.
# It adds that expiration datetime to the payload data under the "exp" key.
# Then it uses PyJWT to encode the payload data with the secret key and HS256 algorithm specified globally in the module. This generates the actual JWT token string.
# Finally, it returns the encoded JWT string.
# So in summary, it takes a dictionary payload, adds the expiration time, encodes it into a JWT, and returns the access token string to use for authentication. The expires_delta parameter allows customizing how long until the token expires.
# The key things happening are:

# • Payload dict with custom data 
# • Expiration time added
# • Encoding using HS256 and the secret key
# • Returning the JWT string

# Let me know if any part needs more explanation!

#----------------------------------------------------------------------------------------------------------------------------


# You're right, let me try explaining that create_access_token function in more depth with some examples.
# The purpose of this function is to take some data, like user information, encode it into a JSON Web Token (JWT), and return that JWT string to use as an access token. 
# JWTs are composed of three parts:

# • Header - specifies the algorithm used, like HS256 
# • Payload - contains claims about the user, permissions, etc
# • Signature - created by encoding header + payload with a secret key

# When you get a JWT, you can decode the header and payload but not the signature without the secret key. That's how they are verified.
# For example, a very basic JWT might look like:
# header.payload.signature
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.hB8eLf1W2Vyk0f_F0eo9_YgCL0tq1Zp9n7Cj8reZzE4
# So in this create_access_token function:

# • The data dict contains custom claims we want encoded, like username
# • expires_delta is used to set an expiration date
# • We encode using HS256 algorithm and our app's secret key

# An example call might look like:
# data = {'sub': 'john'}
# expires = timedelta(minutes=60)
# token = create_access_token(data, expires) 
# This would create a token with a username claim that expires in 60 mins.
# The most important things the function does:

# • Accept custom data to encode
# • Let you easily customize expiration time
# • Handle encoding using the proper algorithm and secret key

# So in summary, it constructs a secured JWT using user data and returns it to use as an access token. The token can then be decoded (except signature) to validate user identity.
# Let me know if any part of that JWT encoding process needs more explanation!

#------------------------------------------------------------------------------------------------------------------------

# Here is a simplified explanation of what that piece of code is doing, along with a simple example:
# The goal of this code is to determine when the access token should expire. It will set the expiration either based on a custom delta that was passed in, or use a default of 15 minutes if no custom value was provided.
# It works like this:
# if expires_delta:
# This checks if an expiration timedelta was passed to the function. For example:
# expires_delta = timedelta(hours=1)  
# If a timedelta was provided, it continues:
#     expire = datetime.now(timezone.utc) + expires_delta
# In this case, it will calculate the expiration by adding the timedelta to the current UTC datetime:
# Current UTC time: 2023-02-28 15:00:00

# expires_delta: timedelta(hours=1) 

# New expiration = Current UTC + Timedelta  
#     = 2023-02-28 15:00:00 + 1 hour 
#     = 2023-02-28 16:00:00
# So it sets the expiration to 1 hour from now.
# On the other hand, if no timedelta was passed: 
# else:
#     expire = datetime.now(timezone.utc) + timedelta(minutes=15)
# It will set the expiration to current UTC time + 15 minutes.
# So in summary, this code determines if a custom expiration was set, and if not uses a 15 minute default. The expiration datetime is set in the UTC timezone.
# Let me know if this helps explain what's happening or if you need any clarification!

#------------------------------------------------------------------------------------------------------------------------

# Got it, let me explain those last few lines in the same simplified way:
# to_encode.update({"exp": expire})
# This adds the expiration datetime we calculated earlier to the payload dictionary:
# to_encode = {
#    'sub': 'john',
#    'role': 'admin'
# }

# expire = 2023-02-28 16:00:00

# to_encode.update({'exp': expire})

# print(to_encode)

# {
#    'sub': 'john', 
#    'role': 'admin',
#    'exp': 2023-02-28 16:00:00
# }
# So it puts the expiration time into the payload that will be encoded.
# encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
# This uses the PyJWT library to encode the full payload dictionary into a JWT string, using the app's secret key and HS256 algorithm:
# to_encode = {
#    'sub': 'john',
#    'role': 'admin',
#    'exp': 2023-02-28 16:00:00 
# }

# encoded_jwt = <long string encoding the above dictionary>
# The output is the full JWT string encoding the payload.
# return encoded_jwt
# Finally, return that encoded JWT string for use as the access token:
# return <long string encoding the payload dictionary> 
# So in summary:

# • Add expiration time to payload
# • Encode entire payload into JWT string
# • Return the JWT to use as access token

# Let me know if this helps explain what those last lines are doing!








async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# This get_current_user async function is used to validate the JWT access token passed in and return the user details if valid. Here is a step-by-step explanation:
# async def get_current_user(token: str):
# Define async function that takes the JWT token as a string parameter.
#     credentials_exception = HTTPException(
#         status_code=401 
#         detail="Could not validate credentials"
#     )
# Define a credentials exception to raise if token is invalid.
#     try:
#         payload = jwt.decode(token, SECRET_KEY, ALGORITHM)
#         username = payload.get("sub")
#         if username is None:
#             raise credentials_exception 

#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception
# Try to decode the JWT token using the secret key. This validates the signature. Extract the username from the payload. If no username, raise the exception. Create a TokenData from the username.
# If decoding fails due to an invalid signature, raise the exception.
#     user = get_user(db, username=token_data.username)
#     if user is None:
#         raise credentials_exception
# Lookup the user from the database using extracted username. Raise an exception if no user found.
#     return user
# If all checks pass, return the validated user details.
# So in summary, it:

# • Validates the JWT signature 
# • Extracts the username from payload
# • Gets user details from database
# • Returns user if valid or raises exception

# This allows securely getting user data from an access token.
# Let me know if any part needs more clarification!








async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user




# Got it, here is a step-by-step explanation of the get_current_active_user function:
# async def get_current_active_user(current_user: User):  
# Define an async function that takes a User model as a parameter.
#     current_user: Depends(get_current_user)
# This line means current_user is injected by calling the get_current_user function we just saw.
# So current_user will be the validated User details extracted from the JWT token.
# For example:
# current_user = User(
#    id=1, 
#    username='john',
#    disabled=False
# )
#     if current_user.disabled:
#         raise HTTPException(400, "Inactive user")
# Check if the user is disabled. If so, raise an exception stating the user is inactive. 
# This prevents disabled users from accessing resources even if they have a valid token.
#    return current_user
# If user is not disabled, return the user object.
# So in summary, this function:

# • Extracts the user from JWT token
# • Checks if user is disabled
# • If not, returns the user

# It's used to guarantee only active users with valid tokens can access resources.
# Let me know if this helps explain what this function is doing!



# You're absolutely right, let me first explain this in more depth before providing examples:
# The purpose of this get_current_active_user function is to add an extra layer of security check beyond just validating the JWT token. 
# Specifically, it checks if the user account associated with that token is disabled or deactivated. This protects sensitive API routes by preventing disabled users from accessing them even if they have a valid JWT token somehow.
# Here is more detail on each part:
# disabled: bool | None = None
# This is a property defined on the User model that indicates if an account is disabled/deactivated. This allows disabling accounts without deleting them from the database.
# For example:
# user1 = User(disabled=False) # active account
# user2 = User(disabled=True) # deactivated  
# So when disabled=True, it means the user account has been deactivated.
# if current_user.disabled:
#    # raise exception
# Here, after extracting the user from the JWT token, it checks if user.disabled = True. 
# If so, it raises an exception stating this user is inactive, blocking access even with a valid token.
# return current_user
# If the check passes and user is active, return the user object.
# So in summary, this adds a check on account status beyond just token validation, ensuring only active users can access sensitive routes. 
# Let me know if the purpose and meaning of the disabled flag makes sense! I can provide some concrete code examples of how this function is used after as well.


# Great question! Let me clarify what it typically means for a user account to be "disabled":
# Disabled in this context usually refers to an account being permanently or temporarily deactivated by an administrator. This is different than something like temporarily locking an account due to failed login attempts.
# Some examples of what could cause an account to be disabled:

# • User violated terms of service or acceptable use policy
# • User has not logged in for an extended period of time (e.g. 6 months)
# • User requested their account to be deactivated
# • Administrator deactivated account due to suspicious activity

# So in summary, a disabled user account generally means:

# • Account has been deactivated (not deleted entirely though)
# • Usually done by an admin or automatically by system 
# • Could be temporary or permanent deactivation
# • User cannot login or access resources while disabled

# This disabled flag allows administrators to easily deactivate accounts without deleting them fully from the database. 
# Compared to locking an account due to failed logins, disabled is usually a more permanent or long-term state until an administrator re-enables it.
# Let me know if this helps explain what the disabled flag represents!



@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

# Sure, let me explain this code line by line with simplicity and examples:
# @app.post("/token")

# • This decorates the function below it as a POST endpoint at /token path of the FastAPI app instance.

# async def login_for_access_token(
#     form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
# ) -> Token:

# • Defines an async function that will handle the login and return an access token
# • It takes in a form_data argument that will contain the username and password
# • The OAuth2PasswordRequestForm and Depends() annotation does validation on the input
# • It returns a Token object that will contain the access token string

# Example form_data:
# {
#   "username": "test",
#   "password": "secret" 
# }
#     user = authenticate_user(fake_users_db, form_data.username, form_data.password)

# • Calls authenticate_user function to verify username and password
# • Passes the username and password from the form_data
# • fake_users_db contains some sample hardcoded users

# Example fake_users_db:
# {
#   "test": {
#     "hashed_password": "$encrypted",
#     ...
#   }
# }
#     if not user:
#        // Raises 401 error

# • If authentication fails, raise a 401 Unauthorized error

#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

# • Create a timedelta of 30 minutes (defined as a constant)

#     access_token = create_access_token() 

# • Call create_access_token to generate a signed JWT token

#     return Token(access_token=access_token, token_type="bearer")

# • Return the token object containing the access token string

# Let me know if any part needs more explanation!

#----------------------------------------------------------------------------------------------------------------------------

# Let me try explaining from the beginning in more depth, using a step-by-step example.
# The goal of this code is to login a user and return an access token that the user can use to access protected resources. 
# @app.post("/token")
# This line decorates the function below it as a POST endpoint. For example, it could be accessed by sending a POST request to http://myapp.com/token.
# async def login_for_access_token(form_data):
# This defines an async function that handles the login logic. 

# • form_data will contain the username and password entered by the user when logging in.

# For example, the frontend app could send a request like:
# POST /token
# {
#     "username": "john",
#     "password": "password123"
# }
#     user = authenticate_user(form_data.username, form_data.password)  
# This calls the authenticate_user function to verify if the username and password are valid.
# Some sample users are stored in the fake_users_db. For example:
# fake_users_db = {
#   "john": {
#     "hashed_password": "$encrypted123"
#   }
# }
# The authenticate_user function compares the entered password to the hashed password to verify the user.
#     if not user:
#        raise 401 error
# If authentication failed, it raises a 401 Unauthorized error.
#     access_token_expires = timedelta(minutes=30) 
# It creates an expiration time of 30 minutes for the access token.
#     access_token = create_access_token(username)
# This calls the create_access_token function to generate an encoded JSON Web Token (JWT) containing the username and expiration time. 
#     return {
#         "access_token": access_token,
#         "token_type": "bearer"
#     }
# It returns the access token in a JSON response to the frontend app. For example: 
# {
#    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...", 
#    "token_type": "bearer"
# }
# The frontend app can use this access token to make requests to protected API endpoints by passing it in the Authorization header.
# Let me know if any part is still unclear!


#------------------------------------------------------------------------------------------------------------------------------



# Sure, let me explain what the "bearer" token type refers to in the same simplified way:
# In the final return statement, we have:
# return {
#     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...", 
#     "token_type": "bearer"
# }
# The "token_type": "bearer" part indicates that the access token being returned follows the Bearer token specification.
# A Bearer token means that whoever holds this token (the "bearer") is authorized to access the API. 
# The client app that gets this token response can then use it by passing it in the Authorization header:
# Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...
# When API endpoints with authentication enabled receive requests, they will:

# • Check for this Authorization header
# • Extract the access token from it 
# • Validate the token to allow or deny access

# So setting the type to "bearer" tells calling clients that they need to send the access token in this standard Bearer token format in order to use that token for authentication.
# Some other common token types include "Basic" for HTTP Basic auth or custom token types. But "bearer" is a very standard approach for API access tokens leveraging OAuth2 flows like in this code.
# Let me know if the purpose behind the "bearer" designation makes more sense now!


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


#------------------------------------------------------------------------------------------------------------------------

# Let me try explaining this endpoint again more simply with an example sequence of steps:

# • Earlier, we logged in a user with username john and got an access token. 

# • The frontend app makes a request to get John's user data:


# GET /users/me
# Authorization: Bearer eyJhbGciOiJIUzI...8n_o

# • The /users/me endpoint is called, along with the access token passed in the Authorization header.

# • The get_current_active_user function gets executed first based on the Depends() annotation.
# current_user = Depends(get_current_active_user)

# • get_current_active_user takes the access token, decodes it to extract the username (john), verifies it is valid and active, and returns a User object:
# {
#   "username": "john",
#   "email": "john@example.com"    
# }

# • This current_user object gets passed to our read_users_me endpoint function. 

# • The function simply returns this user data as the API response:
# return current_user

# • Frontend app gets the user data:
# {
#   "username": "john",
#   "email": "john@example.com"
# }


# So in summary, the access token handling and user data prep all happens in the Depends call, before our endpoint function executes. Our function just returns the current_user data back to the client.
# Let me know if the flow with an example sequence makes more sense!








@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]

#  Got it, I'll explain the next section similarly using a step-by-step example flow:

# • Let's say we make a request to get John's items:

# GET /users/me/items
# Authorization: Bearer <John's access token>

# • This calls the /users/me/items endpoint.  

# • The Depends(get_current_active_user) annotation runs first.

# • It decodes the access token to extract John's username from it.

# • It returns a User object with John's data:


# current_user = {
#   "username": "john",
#   ...
# } 

# • This current_user gets passed to our read_own_items function.

# • Our function returns a list of John's items:


# [
#   {"item_id": "Foo", "owner": "john"}   
# ]
# Here:

# • We used John's username from current_user  to assign as the owner
# • "Foo" is a sample item ID


# • Response sent back:

# [
#   {"item_id": "Foo", "owner": "john"}
# ]
# So in summary, this endpoint:

# • Uses the access token to identify John 
# • Returns a list of items assigned to him

# Let me know if this makes sense explained step-by-step!   