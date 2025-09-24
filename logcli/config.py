"""Configuration settings for the log analyzer."""

# Default bot signatures for filtering
BOT_SIGNATURES = {
    # Traditional bots
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
    'whatsapp', 'telegrambot', 'applebot', 'amazonbot', 'crawl',
    'spider', 'bot', 'scraper', 'curl', 'wget', 'python-requests',
    'postman', 'insomnia', 'httpie',
    
    # AI and LLM bots (new)
    'chatgpt', 'gpt-bot', 'openai', 'gpt-4', 'gpt-3.5',
    'claude', 'anthropic', 'claude-bot', 'bard', 'google-bard', 'palm-bot',
    'copilot', 'github-copilot', 'microsoft-copilot', 'perplexity', 'perplexitybot',
    'ccbot', 'common-crawl', 'commoncrawl', 'ai2bot', 'allen-institute',
    'anthropic-ai', 'claude-web', 'research-bot', 'academic-crawler', 'university-bot',
    'huggingface', 'hf-bot', 'jasper', 'copy.ai', 'writesonic', 'contentbot',
    'midjourney', 'dall-e', 'stable-diffusion', 'imagen', 'ai-seo', 'rank-math-ai',
    'yoast-ai', 'surfer-ai', 'marketo-ai', 'hubspot-ai', 'salesforce-ai',
    'chatbot', 'virtual-assistant', 'dialogflow', 'rasa', 'alexa', 'siri',
    'google-assistant', 'cortana', 'ai-api', 'ml-service', 'neural-bot',
    'tensorflow-bot', 'automated-ai', 'ai-automation', 'ml-automation',
}

# Default status code groups
STATUS_GROUPS = {
    'success': [200, 201, 202, 204, 206],
    'redirect': [301, 302, 303, 304, 307, 308],
    'client_error': [400, 401, 403, 404, 405, 406, 409, 410, 422, 429],
    'server_error': [500, 501, 502, 503, 504, 505]
}

# Default filters
DEFAULT_FILTERS = {
    'countries': [],  # Empty = all countries
    'status_codes': [],  # Empty = all status codes
    'exclude_bots': False,
    'ip_ranges': [],  # CIDR ranges to include/exclude
    'time_range': None,  # (start_time, end_time) tuple
    'methods': [],  # HTTP methods to include
    'paths': [],  # Path patterns to include
}

# Alert thresholds
ALERT_THRESHOLDS = {
    'error_rate': 0.5,  # 50% error rate
    'requests_per_minute': 1000,  # High traffic threshold
    'unique_ips_per_minute': 100,  # Potential attack threshold
}

# Timeline settings
TIMELINE_SETTINGS = {
    'granularity': 'minute',  # minute, hour, day
    'window_size': 60,  # Number of time units to keep in sliding window
    'refresh_interval': 1.0,  # Seconds between UI updates
}

# Export settings
EXPORT_SETTINGS = {
    'csv_delimiter': ',',
    'timestamp_format': '%Y-%m-%d %H:%M:%S',
    'chart_width': 1200,
    'chart_height': 600,
}

# Platform-specific settings
HYPERNODE_SETTINGS = {
    'common_log_paths': [
        '/var/log/nginx/access.log',
        '/var/log/nginx/access.log.1',
        '/data/log/nginx/access.log',
        '/data/log/nginx/access.log.1',
    ],
    'auto_discover_enabled': True,
}

# Platform security toggles and options
PLATFORM_SECURITY = {
    'enable_wordpress': True,
    'enable_woocommerce': True,
    'enable_shopware': True,
    'enable_magento': True,
    # Optional custom admin base path for Magento (e.g., '/admin_xyz/')
    # If empty, defaults to common '/admin' and 'index.php/admin'
    'magento_admin_path': '',
}
