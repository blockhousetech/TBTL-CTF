from selenium.webdriver.common.keys import Keys
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import os
import time

admin_secret = os.getenv('ADMIN_SECRET')

url = f"http://127.0.0.1:5000?secret={admin_secret}"

def visit_page(target_user):
    print('visit_page called', flush=True)

    opts = Options()
    opts.add_argument("-headless")
    opts.binary_location = "/usr/bin/firefox"

    browser = webdriver.Firefox(options=opts)

    try:
        browser.set_page_load_timeout(15)
        browser.get(url + f'&target_user={target_user}')
        browser.implicitly_wait(5)
        browser.quit()
    except Exception as e:
        print(e, flush=True)
        browser.quit()
        print('Came in the exception loop.', flush=True)

    print('visit_page function successfully executed', flush=True)


if __name__ == '__main__':
    visit_page()
