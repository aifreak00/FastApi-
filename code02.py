# # from typing import Annotated

# # from fastapi import Body, FastAPI
# # from pydantic import BaseModel, Field

# # app = FastAPI()


# # class Item(BaseModel):
# #     name: str
# #     description: str | None = Field(
# #         default=None, title="The description of the item", max_length=300
# #     )
# #     price: float = Field(gt=0, description="The price must be greater than zero")
# #     tax: float | None = None


# # @app.put("/items/{item_id}")
# # async def update_item(item_id: int, item: Annotated[Item, Body(embed=True)]):
# #     results = {"item_id": item_id, "item": item}
# #     return results

# from fastapi import FastAPI
# from pydantic import BaseModel

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: str | None = None
#     price: float
#     tax: float | None = None
#     tags: list = []


# @app.put("/items/{item_id}")
# async def update_item(item_id: int, item: Item):
#     results = {"item_id": item_id, "item": item}
#     return results


from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

app = FastAPI()


class Image(BaseModel):
    url: HttpUrl
    name: str


class Item(BaseModel):
    name: str
    description: str | None = None
    price: float
    tax: float | None = None
    tags: set[str] = set()
    image: Image | None = None


@app.put("/items/{item_id}")
async def update_item(item_id: int, item: Item):
    results = {"item_id": item_id, "item": item}
    return results