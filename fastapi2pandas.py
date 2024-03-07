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


#----------------------------------------------------------------------------------------------------------------------

import pandas as pd
import requests

# Make a GET request to your FastAPI endpoint
response = requests.get("http://127.0.0.1:8000/items")

# Check if the request was successful (status code 200)
if response.status_code == 200:
    # Convert the JSON response to a dictionary
    json_data = response.json()
    
    # Create a pandas DataFrame from the JSON data
    df = pd.DataFrame(json_data)
    
    # Display the DataFrame
    print(df)
else:
    # Print an error message if the request was not successful
    print("Error:", response.status_code)
