# from fastapi import FastAPI
# from pydantic import BaseModel

# app = FastAPI()


# class Item(BaseModel):
#     name: str
#     description: str | None = None
#     price: float
#     tax: float | None = None
#     tags: list[str] = []


# @app.post("/items/")
# async def create_item(item: Item) -> Item:
#     return item


# @app.get("/items/")
# async def read_items() -> list[Item]:
#     return [
#         Item(name="Portal Gun", price=42.0),
#         Item(name="Plumbus", price=32.0),
#     ]
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI()

# Define a model for the item
class Item(BaseModel):
    name: str
    description: str = None
    price: float
    tax: float = None
    tags: List[str] = []

# Initialize an empty list to store items
items = []

# Define endpoints
@app.post("/items/")
async def create_item(item: Item) -> Item:
    # Append the received item to the list
    items.append(item)
    # Return the added item
    return item

@app.get("/items/")
async def read_items() -> List[Item]:
    # Return the list of items
    return items
