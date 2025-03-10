import requests
from io import BytesIO
from bs4 import BeautifulSoup  
from pypdf import PdfReader  
import argparse
import logging
import getpass
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logging.getLogger("pypdf").setLevel(logging.ERROR)

def configure_logging(verbose):
    """
    Set the logging level based on the verbose flag.
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

def login_and_get_session(username, password):
    """
    Logs in to the grades site, follows the redirect, and returns:
      (session, token, last_grades_cookie)
    """
    login_url = "https://grades.cs.technion.ac.il/grades.cgi"
    session = requests.Session()
    
    payload = {
        "Login": "1",
        "Course": "",
        "Page": "",
        "SEM": "",
        "ID": username,
        "Password": password,
        "submit": "proceed",
    }
    
    logger.debug("Sending login request to %s", login_url)
    resp = session.post(login_url, data=payload)
    if resp.status_code != 200:
        raise Exception("Login failed or returned non-200 status code (status code: {})".format(resp.status_code))
    
    final_url = resp.url
    logger.debug("Final redirected URL: %s", final_url)
    
    query = final_url.split('?')[1] if '?' in final_url else ''
    token = query.split('+')[0] if '+' in query else query
    if not token:
        raise Exception("Token not found in the redirected URL")
    
    last_grades_cookie = session.cookies.get("LastGradesCookie")
    if not last_grades_cookie:
        raise Exception("LastGradesCookie was not found in the login response cookies.")
    
    logger.debug("Extracted token: %s", token)
    logger.debug("Extracted LastGradesCookie: %s", last_grades_cookie)
    logger.info("Login successful.")
    
    return session, token, last_grades_cookie

def search_in_pdf(pdf_data, keyword):
    """
    Extract text from a PDF (in memory) and search for a keyword.
    Returns True if found, otherwise False.
    """
    pdf_file = BytesIO(pdf_data)
    reader = PdfReader(pdf_file)
    full_text = []
    for page in reader.pages:
        text = page.extract_text() or ""
        full_text.append(text)
    full_text = " ".join(full_text).lower()
    logger.debug("Extracted text snippet from PDF: %s", full_text[:100])
    return keyword.lower() in full_text

def process_html_for_pdfs(html_content, session, keyword):
    """
    Parses HTML content to extract PDF links, fetches and searches each PDF.
    Returns a list of tuples (pdf_url, pdf_filename) where the keyword was found.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    found_pdfs = []
    
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if ".pdf" in href.lower():
            pdf_url = href.strip()
            raw_text = a_tag.get_text(strip=True)
            match = re.search(r'(\S+\.pdf)', raw_text, re.IGNORECASE)
            if match:
                pdf_filename = match.group(1)
            else:
                pdf_filename = raw_text
            logger.debug("Found PDF link: %s (Filename: %s)", pdf_url, pdf_filename)
            
            pdf_resp = session.get(pdf_url)
            if pdf_resp.status_code == 200:
                try:
                    if search_in_pdf(pdf_resp.content, keyword):
                        found_pdfs.append((pdf_url, pdf_filename))
                        logger.debug("Keyword found in PDF: %s", pdf_url)
                except Exception as e:
                    logger.debug("Error processing PDF at %s: %s", pdf_url, e)
            else:
                logger.debug("Failed to fetch PDF: %s, status: %s", pdf_url, pdf_resp.status_code)
    return found_pdfs

def main():
    parser = argparse.ArgumentParser(description="Search PDFs on the grades site.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    configure_logging(args.verbose)
    
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    course_number = input("Course number (e.g. 02340125): ")
    
    try:
        session, token, last_grades_cookie = login_and_get_session(username, password)
    except Exception as e:
        logger.error("Error during login: %s", e)
        return

    search_periods = [
        ("2024", "01"),
        ("2023", "02"),
        ("2023", "01"),
        ("2022", "02"),
        ("2022", "01"),
        ("2021", "02"),
        ("2021", "01"),
        ("2020", "02"),
        ("2020", "01"),
        ("2019", "02"),
        ("2019", "01"),
    ]
    
    while True:
        keyword = input("\nEnter a keyword to search for (or type 'exit' to quit): ").strip()
        if keyword.lower() == "exit":
            print("Bye")
            break
        
        overall_results = []
        for (year, semester) in search_periods:
            url = f"https://grades.cs.technion.ac.il/grades.cgi?{token}+3+{course_number}+{year}{semester}+hw.html"
            logger.debug("Fetching HTML page: %s", url)
            print(f"\nFetching PDFs from: {year}, Semester: {semester}")
            
            resp = session.get(url)
            if resp.status_code == 200:
                html_content = resp.text
                found_pdfs = process_html_for_pdfs(html_content, session, keyword)
                if found_pdfs:
                    for pdf_url, pdf_filename in found_pdfs:
                        overall_results.append((year, semester, pdf_filename, pdf_url))
            else:
                logger.debug("Failed to fetch %s, status code: %s", url, resp.status_code)
        
        if overall_results:
            print("\nKeyword found in the following PDFs:")
            for (year, semester, filename, pdf_url) in overall_results:
                print(f" - Year {year}, Semester {semester}: {filename} ({pdf_url})")
        else:
            print("No matches found for the keyword.")

if __name__ == "__main__":
    main()
