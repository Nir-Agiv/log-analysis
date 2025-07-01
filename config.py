import configparser
import os

# Build the absolute path to the config file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")

# Create a ConfigParser object and read the file
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# --- Main Settings ---
# Split the comma-separated string into a list of log files
LOG_FILES = [f.strip() for f in config.get('main', 'log_files').split(',')]

# --- Rule Settings ---
BRUTE_FORCE_ATTEMPTS = config.getint('rules', 'brute_force_attempts')
BRUTE_FORCE_TIME_WINDOW = config.getint('rules', 'brute_force_time_window')

WEB_SCAN_ATTEMPTS = config.getint('rules', 'web_scan_attempts')
WEB_SCAN_TIME_WINDOW = config.getint('rules', 'web_scan_time_window')