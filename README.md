# Header Guardian

Header Guardian is a Burp Suite extension designed to analyze HTTP request and response headers for security best practices. It provides a user-friendly interface for reviewing headers, highlighting potential security issues, and exporting analysis results.

## Features

- **Context Menu Integration**: Send HTTP requests directly to Header Guardian from anywhere within Burp Suite.
- **Security Header Analysis**: Automatically checks the presence and correctness of critical security headers.
- **Visual Indicators**: Highlights the Header Guardian tab when new requests are sent for analysis.
- **Export to TXT**: Allows you to export the analysis results to a text file for easy sharing and documentation.
- **OWASP Best Practices**: Follows recommendations for HTTP security headers based on the OWASP HTTP Headers Cheat Sheet.

## Installation

1. **Clone or Download the Repository:**

   ```bash
   git clone https://github.com/oldermutt/HeaderGuardian.git
   
2.  **Load the Extension in Burp Suite:**

    -   Open Burp Suite.
    -   Go to the "Extensions" tab and click on the "Add" button.
    -   Select "Java" as the extension type.
    -   Load the `HeaderGuardian.py` file from the cloned repository.
3.  **Start Using the Extension:**

    -   The extension will add a new tab labeled "Header Guardian" in Burp Suite.
    -   You can now right-click on any HTTP request in Burp Suite and select "Send to Header Guardian" to analyze it.

Usage
-----

1.  **Sending Requests to Header Guardian:**

    -   Right-click on any HTTP request in Burp Suite.
    -   Select "Send to Header Guardian" from the context menu.
    -   The Header Guardian tab will be highlighted, indicating that a new request has been added.
2.  **Analyzing Headers:**

    -   In the Header Guardian tab, the request and response headers will be displayed.
    -   The analysis panel will show a table with the current value, expected value, and status of each header.
    -   Headers that are missing, misconfigured, or unnecessary will be flagged accordingly.
3.  **Exporting Analysis:**

    -   Click on the "Export to TXT" button at the bottom of the analysis panel.
    -   Choose the location to save the file, and the analysis will be saved in a text file.
  
Examples
--------
<img width="959" alt="image" src="https://github.com/user-attachments/assets/e3e610f5-118a-40fe-9129-19757c9d9701">


License
-------

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

Contributing
------------

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.

Contact
-------

For any questions or issues, please contact oldermutt@proton.me

Acknowledgments
---------------

-   This extension follows recommendations for HTTP security headers from OWASP. For more details, refer to the [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
