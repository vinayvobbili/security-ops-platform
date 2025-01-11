import os
from typing import List

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Initialize FastAPI app
app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/charts", StaticFiles(directory="../charts"), name="charts")  # Serve the 'charts' directory as well

# Configure Jinja2 templates
templates = Jinja2Templates(directory=".")

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")


def get_image_files() -> List[str]:
    """Retrieves a list of image files from the static and charts directories."""
    image_files = []

    for directory, prefix in (("static/images", ""), ("../charts", "charts/")):  # add prefix for chart images
        for filename in os.listdir(directory):
            if filename.endswith(IMAGE_EXTENSIONS):
                image_files.append(prefix + filename)  # Prefix filenames from charts directory
    return image_files


# Pre-defined image order for display
IMAGE_ORDER = [
    "Company Logo.jpg",
    "GDnR Coin.png",
    "IR_Metrics.jpeg",
    "Aging Tickets.png",
    "Inflow.png",
    "SLA Breaches.png",
    "MTTR-MTTC.png",
    "Outflow.png",
    "Heatmap.png",
    "charts/de_stories.png",
    "charts/re_stories.png",
    "Feedback Email.png",
    "Thanks.png"
]


@app.get("/full", response_class=HTMLResponse)
async def read_root(request: Request):
    """Renders the HTML template with the ordered list of image files."""

    image_files = get_image_files()
    # Sort image files according to the predefined order
    image_files.sort(key=lambda x: IMAGE_ORDER.index(x) if x in IMAGE_ORDER else len(IMAGE_ORDER))

    return templates.TemplateResponse("index.html", {"request": request, "image_files": image_files})


if __name__ == "__main__":
    uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)
