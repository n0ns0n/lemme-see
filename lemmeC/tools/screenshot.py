import base64
import requests
from .noimage import noImage

class Screenshoter:

    def __init__(self, target, keys):
        self.api_keys = keys
        self.target = target
        self.current_key = 0
        self.api_url = "https://api.apiflash.com/v1/urltoimage"
        
    def take_screenshot(self):
        loop = True
        screenshot = noImage
        while loop:
            params = {
                "access_key":self.api_keys[self.current_key],
                "url": self.target
            }
            req = requests.get(self.api_url, params=params)
            if req.status_code == 402:
                print(f"[!](ApiFlash) Quota exceeded for key:{self.api_keys[self.current_key]}")
                print(f"[+](ApiFlash) Trying to use a different one") 
                self.current_key += 1
                if self.current_key > len(self.api_keys) - 1:
                    print(f"[!](ApiFlash) No more available API keys to use.")
                    loop = False
            elif req.status_code == 200:
                loop = False
                print(f"[+](ApiFlash) Took screenshot from: {self.target}")
                screenshot = base64.b64encode(req.content).decode()
            else:
                print(f"[!](ApiFlash) Could not take screenshot for:{self.target} ({req.status_code})")
                loop = False

        return screenshot
                
        
    