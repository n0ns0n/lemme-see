import base64
import requests
from .noimage import noImage

class Screenshoter:

    def __init__(self, target, is_active, api_keys):
        self.target = target
        self.is_active = is_active
        self.api_url = "https://api.apiflash.com/v1/urltoimage"
        self.screenshot = None
        self.api_keys = api_keys
    
    def take_screenshot_apiflash(self):
        if not self.api_keys:
            print(f"[!](Screenshoter:ApiFlash) No available API keys to use.")
            return False

        current_key = 0
        while True:
            params = {
                "access_key":self.api_keys[current_key],
                "url": self.target
            }
            req = requests.get(self.api_url, params=params)
            if req.status_code == 402:
                print(f"[!](Screenshoter:ApiFlash) Quota exceeded for key:{self.api_keys[current_key]}")
                print(f"[+](Screenshoter:ApiFlash) Trying to use a different one") 
                current_key += 1
                if current_key > len(self.api_keys) - 1:
                    print(f"[!](Screenshoter:ApiFlash) No more available API keys to use.")
                    return False 
            elif req.status_code == 200:
                self.screenshot = base64.b64encode(req.content).decode()
                return True
            else:
                return False
                
    def take_screenshot_active(self):
        self.screenshot = noImage
        input("[!](Screenshoter:Active) Press enter to continue...")
        return True

    def take_screenshot(self):
        if self.is_active:
            print(f"[i](Screenshoter:Active) Trying to take screenshot for: {self.target}")
            if self.take_screenshot_active():
                print(f"[+](Screenshoter:Active) Took screenshot for: {self.target}")
                return self.screenshot
            else:
                print(f"[!](Screenshoter:Active) Could not take screenshot for: {self.target}")
                return noImage
        else:
            print(f"[i](Screenshoter:ApiFlash) Trying to take screenshot for: {self.target}")
            if self.take_screenshot_apiflash():
                print(f"[+](Screenshoter:ApiFlash) Took screenshot for: {self.target}")
                return self.screenshot
            else:
                print(f"[!](Screenshoter:ApiFlash) Could not take screenshot for: {self.target}")
                return noImage



