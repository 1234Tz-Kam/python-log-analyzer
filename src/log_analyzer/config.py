
# Security detection configuration

FAILED_LOGIN_THRESHOLD = 5

TIME_WINDOW_MINUTES = 5

HIGH_SEVERITY_THRESHOLD = 10

# Standard SSH syslog entries omit the year.
# Our synthetic sample logs use 2026.
DEFAULT_LOG_YEAR = 2026
