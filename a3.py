# from typing import Annotated

# from fastapi import Cookie, FastAPI

# app = FastAPI()


# @app.get("/items/")
# async def read_items(ads_id: Annotated[str | None, Cookie()] = None):
#     return {"ads_id": ads_id}

# from typing import Annotated

# from fastapi import FastAPI, Header

# app = FastAPI()


# @app.get("/items/")
# async def read_items(user_agent: Annotated[str | None, Header()] = None):
#     return {"User-Agent": user_agent}


# from typing import Annotated

# from fastapi import FastAPI, Header

# app = FastAPI()


# @app.post("/items/")
# async def read_items(
#     strange_header: Annotated[str | None, Header(convert_underscores=False)] = None
# ):
#     return {"strange_header": strange_header}

from typing import Annotated

from fastapi import FastAPI, Header

app = FastAPI()


@app.get("/items/")
async def read_items(x_token: Annotated[list[str] | None, Header()] = None):
    return {"X-Token values": x_token}