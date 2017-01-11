# Udacity Catalog Project
This project implements the Catalog project from the Full Stack Developer Nanodegree.

The project does the following:
* Uses Facebook and Google OAuth implementations to log users in
* Allows CRUD operations on categories and items of a catalog
* Provides a JSON API endpoint to retrieve data from the catalog

# Local set up
If you would like to run the code locally, you will need to do the following.
* 1. Acquire a Google API key from https://console.developers.google.com/apis/
* 2. Download your API to a json file named 'google_client_secrets.json' and place it in the same directory as application.py
* 3. Acquire a Facebook API key from https://developers.facebook.com/docs/pages/getting-started
* 4. Create a file called 'facebook_client_secrets.json' in the same directory as application.py. The structure of this file should be:
{"web": {"app_access_token": "YOUR_APP_ID", "app_secret": "YOUR_APP_SECRET"}}
* 5. Run `python application.py` and browse to localhost:8000
