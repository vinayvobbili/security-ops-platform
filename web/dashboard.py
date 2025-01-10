import os

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

# Mount static files
# app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure Jinja2 templates
templates = Jinja2Templates(directory=".")


# Get the list of image files
def get_image_files():
    image_files = []
    for filename in os.listdir("static/images"):  # Updated path
        if filename.endswith((".jpg", ".jpeg", ".png", ".gif", ".svg")):  # Check for common image extensions
            image_files.append(filename)
    return image_files


@app.get("/full", response_class=HTMLResponse)
async def read_root(request: Request):
    image_files = get_image_files()
    order = [
        "Company Logo.jpg",
        "GDnR Coin.png",
        "IR_Metrics_.jpeg",
        "Aging Tickets.png",
        "Inflow.png",
        "SLA Breaches.png",
        "MTTR-MTTC.png",
        "Outflow.png",
        "Heatmap.png",
        "Feedback Email.png",
        "Thanks.png"
    ]
    image_files.sort(key=lambda x: order.index(x))

    return templates.TemplateResponse("index.html", {"request": request, "image_files": image_files})


if __name__ == "__main__":
    uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)
