import os
from typing import List

import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from services import transfer_ticket

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
    "charts/Threatcon Level.png",
    "charts/Days Since Last Incident.jpg",
    "charts/Aging Tickets.png",
    "charts/Inflow Yesterday.png",
    "charts/SLA Breaches.png",
    "charts/MTTR MTTC.png",
    "charts/Outflow Yesterday.png",
    "charts/Heatmap.png",
    "charts/Days Since Last Incident.jpg",
    "charts/Vectra Detections by Rule.png",
    "charts/DE Stories.png",
    "charts/RE Stories.png",
    "End of presentation.jpg",
    "Feedback Email.png",
    "Thanks.png",
]


@app.get("/full-slide-show", response_class=HTMLResponse)
async def get_ir_dashboard_charts(request: Request):
    """Renders the HTML template with the ordered list of image files."""

    image_files = get_image_files()
    # Sort image files according to the predefined order
    image_files.sort(key=lambda x: IMAGE_ORDER.index(x) if x in IMAGE_ORDER else len(IMAGE_ORDER))

    return templates.TemplateResponse("index.html", {"request": request, "image_files": image_files})


@app.get("/msoc-form", response_class=HTMLResponse)
async def display_form(request: Request):
    """Displays the MSOC form."""
    return templates.TemplateResponse("msoc_form.html", {"request": request})


@app.post("/submit-msoc-form", response_class=HTMLResponse)
async def handle_msoc_form_submission(request: Request, site: str = Form(...), server: str = Form(...)):
    """Handles MSOC form submissions and processes the data."""

    # Process the submitted data.  For example, print it:
    print(f"Site: {site}")
    print(f"Server: {server}")

    # You can then redirect to a success page, return a response, or process the data further
    return templates.TemplateResponse("msoc_success.html", {"request": request, "site": site, "server": server})


@app.get("/xsoar-ticket-import-form", response_class=HTMLResponse)
async def display_form(request: Request):
    """Displays the MSOC form."""
    return templates.TemplateResponse("xsoar-ticket-import-form.html", {"request": request})


@app.post("/import-xsoar-ticket", response_class=HTMLResponse)
async def handle_msoc_form_submission(request: Request, source_ticket_number: str = Form(...)):
    """Handles MSOC form submissions and processes the data."""

    print(f"Source ticket number: {source_ticket_number}")
    destination_ticket_number, destination_ticket_link = transfer_ticket.import_ticket(source_ticket_number)
    return templates.TemplateResponse("xsoar-ticket-import-response.html", {
        "request": request,
        "source_ticket_number": source_ticket_number,
        "destination_ticket_number": destination_ticket_number,
        "destination_ticket_link": destination_ticket_link
    })


if __name__ == "__main__":
    uvicorn.run("web_server:app", host="0.0.0.0", port=8000, reload=True)
