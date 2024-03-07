# This middleware adds a custom header X-Process-Time to the response. 
# Specifically, it:

# • Calculates the time taken to process each request 
# • Adds this processing time to the response headers
# • The added X-Process-Time header contains the time in seconds

# So why would you want to do this?
# Some potential uses:

# • Monitor application performance - You can check the processing time per request to detect slow endpoints.

# • Debugging - If some requests unexpectedly take too long, the added header makes it easy to identify.

# • Optimizing caches - You can check if caching is working correctly by verifying that cached response times are faster.

# • Identifying slow clients - Some client devices/networks may connect slower, reflected in processing time.


# So while a simple header addition, it enables some useful monitoring, debugging and performance use cases.
# The key takeaway is that middleware lets you transparently modify every request and response of an application. This allows implementing cross-cutting concerns in a single place.
# Some other common middleware uses:

# • Authentication 
# • Logging
# • Compression
# • Caching
# • Rate limiting

# Let me know if this helps explain the purpose and value of adding this processing time header!

import time

from fastapi import FastAPI, Request

app = FastAPI()


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


#  Here is an explanation of what this FastAPI middleware code is doing:
# import time
# from fastapi import FastAPI, Request

# app = FastAPI()
#  Imports required packages - time, FastAPI, Request
#  Creates a FastAPI app instance
# @app.middleware("http")
# async def add_process_time_header(request: Request, call_next):
#  Defines a middleware function using the @app.middleware decorator
#  Middleware will execute on every HTTP request
#  Function takes request and call_next as arguments
#     start_time = time.time()
#     response = await call_next(request)
#  Before request is handled, it records start time 
#  call_next passes request to next middleware/route handler in chain 
#  Returns the response once route handler returns 
#     process_time = time.time() - start_time
#     response.headers["X-Process-Time"] = str(process_time)
#     return response
#  After response, calculates time taken to process request
#  Adds this time taken in a custom X-Process-Time header 
#  Returns response
# So in summary, this middleware attaches a custom header with time take for request to be processed, without modifying any application code!
# Let me know if any part is still unclear!   