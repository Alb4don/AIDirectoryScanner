# Features

- Picks up on server behavior and adjusts accordingly.
- Distinguishes real discoveries from false alarms.
- Automatically throttles requests to avoid overwhelming servers.

![AI](https://github.com/user-attachments/assets/70def9a9-92bd-473f-9aab-8501c6703be7)

# Install

- You'll need Python 3.6 or newer and a couple of packages:

        pip install requests urllib3

- you're ready to go:

        git clone https://github.com/Alb4don/AIDirectoryScanner.git

        cd AIDirectoryScanner
        chmod +x ai_dirscan.py

# How to Use It

- Basic scan of a single target:

        python3 ai_dirscan.py -u test.com
  
- Hit multiple targets at once:

        python3 ai_dirscan.py -u test.com target2.com target3.com

- Bring your own wordlist:

        python3 ai_dirscan.py -u test.com -l /path/to/wordlist.txt

# Tweaking the Behavior

- You can modify these settings in the code:

        base_delay = 0.1    
        max_delay = 2.0     

        max_cache_entries = 1000    
  
        max_generated_paths = 50

# Disclaimer

- This tool is for educational and authorized testing only. We're not responsible if you use this inappropriately.
