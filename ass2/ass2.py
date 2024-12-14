import re
import requests
import urllib3


# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


API_KEY = "e3483f413198a1f057a2bf691c0cb0602996fe953e49b15a061815743e90c582"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"


def load_blacklist(filename="blacklist.txt"):
    try:
        with open(filename, "r") as file:
            return {line.strip().lower() for line in file}
    except FileNotFoundError:
        print("Blacklist file not found.")
        return set()


def extract_url(text):
    url_pattern = re.compile(r"https?://\S+|www\.\S+")
    match = url_pattern.search(text)
    return match.group(0) if match else None


def check_url_safety(url):
    params = {"apikey": API_KEY, "resource": url}
    try:
        response = requests.get(VIRUSTOTAL_URL, params=params, verify=False)
        response.raise_for_status()
        result = response.json()

        if result.get("response_code") == 1:
            if result.get("positives", 0) > 0:
                return f"WARNING: The URL '{url}' is flagged as malicious."
            else:
                return f"The URL '{url}' is safe."
        else:
            return "Could not check the URL. It might be invalid or unavailable."
    except requests.exceptions.RequestException as e:
        return f"An error occurred while checking the URL: {e}"
    except ValueError:
        return "Error: The response from VirusTotal was not in a valid JSON format."


def contains_blacklisted_word(text, blacklist):
    words = text.lower().split()
    blacklisted_words = {word for word in words if word in blacklist}
    if blacklisted_words:
        return f"Text contains blacklisted words: {', '.join(blacklisted_words)}"
    return "No blacklisted words detected."


def main():
    blacklist = load_blacklist()
    print("Enter text to check for URLs and blacklisted words (type 'Stop' to exit).")

    while True:
        user_input = input("Enter text: ").strip()
        if user_input.lower() == "stop":
            print("Exiting the program.")
            break

        url = extract_url(user_input)
        if url:
            print(check_url_safety(url))
        else:
            print("No URL found.")

        print(contains_blacklisted_word(user_input, blacklist))
        print("-" * 50)


if __name__ == "__main__":
    main()
