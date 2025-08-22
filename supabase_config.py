# Supabase Configuration
# Replace these with your actual Supabase project credentials

# Your Supabase project URL (from Settings → API in your Supabase dashboard)
SUPABASE_URL = "https://slakouynoaldqaltjepc.supabase.co"  # Replace with your actual project URL

# Your Supabase anon/public key (from Settings → API in your Supabase dashboard)
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNsYWtvdXlub2FsZHFhbHRqZXBjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQ1Mzc0NTcsImV4cCI6MjA3MDExMzQ1N30.L_4XPXmz4bAqOMbgVPebN_ihCEklVO8Ky-ztGq6tBZg"  # Replace with your actual anon key

# Database table names (adjust these to match your actual table names)
LICENSES_TABLE = "licenses"  # Table containing license information
HEARTBEATS_TABLE = "heartbeats"  # Table for storing heartbeat data
USERS_TABLE = "users"  # Table for user information (if separate)

# License status constants
LICENSE_STATUS_ACTIVE = "active"
LICENSE_STATUS_INACTIVE = "inactive"
LICENSE_STATUS_EXPIRED = "expired"
LICENSE_STATUS_SUSPENDED = "suspended"

# License types
LICENSE_TYPE_STANDARD = "standard"
LICENSE_TYPE_PREMIUM = "premium"
LICENSE_TYPE_TRIAL = "trial"
LICENSE_TYPE_LIFETIME = "lifetime"
