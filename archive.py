# archive.py
import requests

def archive_page(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            filename = f'archives/{url.replace("://", "_").replace("/", "_")}.html'
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(response.text)
            return filename
    except Exception as e:
        print(f'Error archiving page: {e}')
    return None
