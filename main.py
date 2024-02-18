import customtkinter as ctk
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os

# Define the scopes required for accessing Google Drive
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']

class GoogleDriveApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Google Drive Explorer")
        self.geometry("600x400")

        # Initialize the Google Drive API
        self.service = self.initialize_drive_service()

        # Create GUI components
        self.file_textbox = ctk.CTkTextbox(self, width=60, height=20)
        self.file_textbox.pack(expand=True, fill='both')

        # Populate file list
        self.populate_file_list()

    def initialize_drive_service(self):
        # Load credentials from file or perform OAuth flow
        creds = self.load_credentials()

        # Build the service object
        service = None
        if creds:
            service = build('drive', 'v3', credentials=creds)
        return service

    def load_credentials(self):
        # Load saved credentials or perform OAuth flow
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json')
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secret_699899135019-uar0620uv47bjdjddkfvoupig2naacsk.apps.googleusercontent.com.json', SCOPES)
            creds = flow.run_local_server(port=0)
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        return creds

    def populate_file_list(self):
        # Call the Drive API to list files
        results = self.service.files().list(
            pageSize=10, fields="nextPageToken, files(id, name)").execute()
        items = results.get('files', [])

        # Append files to the textbox with separators
        file_list = ""
        for item in items:
            file_list += f"{item['name']}\n{'-' * 40}\n"
        self.file_textbox.insert(ctk.END, file_list)

if __name__ == "__main__":
    app = GoogleDriveApp()
    app.mainloop()