import requests

def test_reverse_proxy(url, expected_status=200, expected_text=None):
    """
    Tests if the reverse proxy is working correctly by sending a request to the specified URL.

    Args:
        url (str): The URL of the reverse proxy.
        expected_status (int): The expected HTTP status code. Default is 200.
        expected_text (str): A substring of the expected text in the response body.

    Returns:
        bool: True if the reverse proxy is working as expected, False otherwise.
    """
    try:
        response = requests.get(url)
        if response.status_code != expected_status:
            print(f"Failed: Expected status {expected_status}, got {response.status_code}")
            return False
        
        if expected_text and expected_text not in response.text:
            print(f"Failed: Expected text not found in response body.")
            return False

        print(f"Success: Reverse proxy is working correctly for {url}")
        return True

    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to reach the reverse proxy at {url}. Exception: {e}")
        return False

def main():
    # List of URLs to test with expected status codes and text.
    tests = [
        {"url": "http://your-reverse-proxy-domain.com", "expected_status": 200, "expected_text": "Welcome to my website"},
        {"url": "http://your-reverse-proxy-domain.com/another-service", "expected_status": 200, "expected_text": "Another Service"},
        # Add more test cases as needed
    ]
    
    all_tests_passed = True
    
    for test in tests:
        url = test["url"]
        expected_status = test.get("expected_status", 200)
        expected_text = test.get("expected_text", None)
        
        if not test_reverse_proxy(url, expected_status, expected_text):
            all_tests_passed = False

    if all_tests_passed:
        print("All tests passed!")
    else:
        print("Some tests failed. Please check the reverse proxy configuration.")

if __name__ == "__main__":
    main()
