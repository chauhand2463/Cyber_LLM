import requests
from typing_extensions import Annotated
from pypdf import PdfReader
from bs4 import BeautifulSoup
import io
import json

import utils.constants

PDF_WORKING_FOLDER = utils.constants.LLM_WORKING_FOLDER + "/pdf"


def download_pdf_report(
    url: Annotated[
        str,
        "The URL of the PDF report to download",
    ]
) -> Annotated[str, "The content of the PDF report"]:

    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Save to file
        pdf_path = f"{PDF_WORKING_FOLDER}/tmp.pdf"
        with open(pdf_path, "wb") as f:
            f.write(response.content)

        reader = PdfReader(pdf_path)
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"

        return text
    except Exception as e:
        return f"Error downloading PDF: {e}"


def download_web_page(
    url: Annotated[
        str,
        "The URL of the web page to download",
    ]
) -> Annotated[str, "The content of the web page"]:

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.get_text(strip=True)
    except Exception as e:
        return f"Error downloading webpage: {e}"


def detect_telemetry_gaps(
    url: Annotated[
        str,
        "The URL of the EDR telemetry JSON file to download",
    ],
    edr_name: Annotated[
        str,
        "The name of the EDR",
    ],
) -> Annotated[
    str, "The overview of all EDR telemetry categories not detected by the EDR"
]:
    try:
        # Download JSON
        response = requests.get(url)
        response.raise_for_status()
        
        data = response.json()
        
        # Filter logic equivalent to jq '.[] | select(.{edr_name} == "No") | .["Sub-Category"]'
        gaps = []
        for entry in data:
            # Check if key exists and equals "No"
            if entry.get(edr_name) == "No":
                sub_cat = entry.get("Sub-Category")
                if sub_cat:
                    gaps.append(sub_cat)
        
        return "\n".join(gaps)
        
    except Exception as e:
        return f"Error detecting gaps: {e}"
