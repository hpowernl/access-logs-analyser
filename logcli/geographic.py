"""Geographic analysis module for IP geolocation and threat mapping."""

import json
import requests
import sqlite3
import gzip
import csv
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple, Optional
from pathlib import Path
import ipaddress
from rich.console import Console

console = Console()


class GeoIPAnalyzer:
    """Analyzes geographic distribution and threat patterns."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the geographic analyzer."""
        self.db_path = db_path or "geoip.db"
        self.country_stats = defaultdict(lambda: {
            'total_requests': 0,
            'unique_ips': set(),
            'error_requests': 0,
            'bot_requests': 0,
            'threat_score': 0.0,
            'avg_response_time': 0.0,
            'response_times': [],
            'bandwidth_bytes': 0,
            'attack_attempts': defaultdict(int),
            'top_paths': Counter(),
            'top_user_agents': Counter(),
            'status_codes': Counter(),
            'hourly_distribution': defaultdict(int),
            'suspicious_ips': set(),
            'legitimate_crawlers': set()
        })
        
        self.ip_to_country = {}
        self.threat_countries = set()
        self.high_volume_countries = set()
        
        # Initialize GeoIP database
        self._init_geoip_db()
        
    def _init_geoip_db(self):
        """Initialize or create GeoIP database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS geoip (
                    network TEXT PRIMARY KEY,
                    country_code TEXT,
                    country_name TEXT,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    timezone TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_network ON geoip(network)')
            
            conn.commit()
            conn.close()
            
            # Check if we have data, if not, try to download basic GeoIP data
            if self._get_db_record_count() == 0:
                console.print("[yellow]GeoIP database is empty. Consider downloading GeoIP data for better accuracy.[/yellow]")
                self._create_basic_country_mappings()
                
        except Exception as e:
            console.print(f"[red]Error initializing GeoIP database: {str(e)}[/red]")
            # Fall back to basic country detection
            self._create_basic_country_mappings()
    
    def _get_db_record_count(self) -> int:
        """Get number of records in GeoIP database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM geoip')
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except:
            return 0
    
    def _create_basic_country_mappings(self):
        """Create basic country mappings for common IP ranges."""
        # Basic mappings for common cloud providers and known ranges
        basic_mappings = {
            # Google Cloud
            '8.8.8.0/24': 'US',
            '8.8.4.0/24': 'US',
            '8.34.208.0/20': 'US',
            '8.35.192.0/20': 'US',
            
            # Amazon AWS
            '52.0.0.0/8': 'US',
            '54.0.0.0/8': 'US',
            
            # Microsoft Azure
            '13.0.0.0/8': 'US',
            '20.0.0.0/8': 'US',
            
            # Cloudflare
            '104.16.0.0/12': 'US',
            '172.64.0.0/13': 'US',
            
            # European ranges (approximations)
            '185.0.0.0/8': 'EU',
            '194.0.0.0/8': 'EU',
            '195.0.0.0/8': 'EU',
            
            # Netherlands specific
            '62.45.0.0/16': 'NL',
            '85.17.0.0/16': 'NL',
            '185.37.0.0/16': 'NL',
            '217.105.0.0/16': 'NL',
            
            # Germany specific
            '87.167.0.0/16': 'DE',
            '95.90.0.0/16': 'DE',
            '144.76.0.0/16': 'DE',
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for network, country in basic_mappings.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO geoip (network, country_code, country_name)
                    VALUES (?, ?, ?)
                ''', (network, country, self._get_country_name(country)))
            
            conn.commit()
            conn.close()
            console.print(f"[green]Created basic GeoIP mappings for {len(basic_mappings)} networks[/green]")
            
        except Exception as e:
            console.print(f"[yellow]Could not create basic mappings: {str(e)}[/yellow]")
    
    def _get_country_name(self, country_code: str) -> str:
        """Get full country name from country code."""
        country_names = {
            # Special/common extras
            'EU': 'Europe (Generic)',
            'XK': 'Kosovo',

            # ISO 3166-1 alpha-2
            'AD': 'Andorra',
            'AE': 'United Arab Emirates',
            'AF': 'Afghanistan',
            'AG': 'Antigua and Barbuda',
            'AI': 'Anguilla',
            'AL': 'Albania',
            'AM': 'Armenia',
            'AO': 'Angola',
            'AQ': 'Antarctica',
            'AR': 'Argentina',
            'AS': 'American Samoa',
            'AT': 'Austria',
            'AU': 'Australia',
            'AW': 'Aruba',
            'AX': 'Åland Islands',
            'AZ': 'Azerbaijan',
            'BA': 'Bosnia and Herzegovina',
            'BB': 'Barbados',
            'BD': 'Bangladesh',
            'BE': 'Belgium',
            'BF': 'Burkina Faso',
            'BG': 'Bulgaria',
            'BH': 'Bahrain',
            'BI': 'Burundi',
            'BJ': 'Benin',
            'BL': 'Saint Barthélemy',
            'BM': 'Bermuda',
            'BN': 'Brunei Darussalam',
            'BO': 'Bolivia (Plurinational State of)',
            'BQ': 'Bonaire, Sint Eustatius and Saba',
            'BR': 'Brazil',
            'BS': 'Bahamas',
            'BT': 'Bhutan',
            'BV': 'Bouvet Island',
            'BW': 'Botswana',
            'BY': 'Belarus',
            'BZ': 'Belize',
            'CA': 'Canada',
            'CC': 'Cocos (Keeling) Islands',
            'CD': 'Congo (the Democratic Republic of the)',
            'CF': 'Central African Republic',
            'CG': 'Congo',
            'CH': 'Switzerland',
            'CI': "Côte d’Ivoire",
            'CK': 'Cook Islands',
            'CL': 'Chile',
            'CM': 'Cameroon',
            'CN': 'China',
            'CO': 'Colombia',
            'CR': 'Costa Rica',
            'CU': 'Cuba',
            'CV': 'Cabo Verde',
            'CW': 'Curaçao',
            'CX': 'Christmas Island',
            'CY': 'Cyprus',
            'CZ': 'Czechia',
            'DE': 'Germany',
            'DJ': 'Djibouti',
            'DK': 'Denmark',
            'DM': 'Dominica',
            'DO': 'Dominican Republic',
            'DZ': 'Algeria',
            'EC': 'Ecuador',
            'EE': 'Estonia',
            'EG': 'Egypt',
            'EH': 'Western Sahara',
            'ER': 'Eritrea',
            'ES': 'Spain',
            'ET': 'Ethiopia',
            'FI': 'Finland',
            'FJ': 'Fiji',
            'FK': 'Falkland Islands (Malvinas)',
            'FM': 'Micronesia (Federated States of)',
            'FO': 'Faroe Islands',
            'FR': 'France',
            'GA': 'Gabon',
            'GB': 'United Kingdom',
            'GD': 'Grenada',
            'GE': 'Georgia',
            'GF': 'French Guiana',
            'GG': 'Guernsey',
            'GH': 'Ghana',
            'GI': 'Gibraltar',
            'GL': 'Greenland',
            'GM': 'Gambia',
            'GN': 'Guinea',
            'GP': 'Guadeloupe',
            'GQ': 'Equatorial Guinea',
            'GR': 'Greece',
            'GS': 'South Georgia and the South Sandwich Islands',
            'GT': 'Guatemala',
            'GU': 'Guam',
            'GW': 'Guinea-Bissau',
            'GY': 'Guyana',
            'HK': 'Hong Kong',
            'HM': 'Heard Island and McDonald Islands',
            'HN': 'Honduras',
            'HR': 'Croatia',
            'HT': 'Haiti',
            'HU': 'Hungary',
            'ID': 'Indonesia',
            'IE': 'Ireland',
            'IL': 'Israel',
            'IM': 'Isle of Man',
            'IN': 'India',
            'IO': 'British Indian Ocean Territory',
            'IQ': 'Iraq',
            'IR': 'Iran (Islamic Republic of)',
            'IS': 'Iceland',
            'IT': 'Italy',
            'JE': 'Jersey',
            'JM': 'Jamaica',
            'JO': 'Jordan',
            'JP': 'Japan',
            'KE': 'Kenya',
            'KG': 'Kyrgyzstan',
            'KH': 'Cambodia',
            'KI': 'Kiribati',
            'KM': 'Comoros',
            'KN': 'Saint Kitts and Nevis',
            'KP': "Korea (the Democratic People's Republic of)",
            'KR': 'Korea (the Republic of)',
            'KW': 'Kuwait',
            'KY': 'Cayman Islands',
            'KZ': 'Kazakhstan',
            'LA': "Lao People's Democratic Republic",
            'LB': 'Lebanon',
            'LC': 'Saint Lucia',
            'LI': 'Liechtenstein',
            'LK': 'Sri Lanka',
            'LR': 'Liberia',
            'LS': 'Lesotho',
            'LT': 'Lithuania',
            'LU': 'Luxembourg',
            'LV': 'Latvia',
            'LY': 'Libya',
            'MA': 'Morocco',
            'MC': 'Monaco',
            'MD': 'Moldova (the Republic of)',
            'ME': 'Montenegro',
            'MF': 'Saint Martin (French part)',
            'MG': 'Madagascar',
            'MH': 'Marshall Islands',
            'MK': 'North Macedonia',
            'ML': 'Mali',
            'MM': 'Myanmar',
            'MN': 'Mongolia',
            'MO': 'Macao',
            'MP': 'Northern Mariana Islands',
            'MQ': 'Martinique',
            'MR': 'Mauritania',
            'MS': 'Montserrat',
            'MT': 'Malta',
            'MU': 'Mauritius',
            'MV': 'Maldives',
            'MW': 'Malawi',
            'MX': 'Mexico',
            'MY': 'Malaysia',
            'MZ': 'Mozambique',
            'NA': 'Namibia',
            'NC': 'New Caledonia',
            'NE': 'Niger',
            'NF': 'Norfolk Island',
            'NG': 'Nigeria',
            'NI': 'Nicaragua',
            'NL': 'Netherlands',
            'NO': 'Norway',
            'NP': 'Nepal',
            'NR': 'Nauru',
            'NU': 'Niue',
            'NZ': 'New Zealand',
            'OM': 'Oman',
            'PA': 'Panama',
            'PE': 'Peru',
            'PF': 'French Polynesia',
            'PG': 'Papua New Guinea',
            'PH': 'Philippines',
            'PK': 'Pakistan',
            'PL': 'Poland',
            'PM': 'Saint Pierre and Miquelon',
            'PN': 'Pitcairn',
            'PR': 'Puerto Rico',
            'PS': 'Palestine, State of',
            'PT': 'Portugal',
            'PW': 'Palau',
            'PY': 'Paraguay',
            'QA': 'Qatar',
            'RE': 'Réunion',
            'RO': 'Romania',
            'RS': 'Serbia',
            'RU': 'Russia',
            'RW': 'Rwanda',
            'SA': 'Saudi Arabia',
            'SB': 'Solomon Islands',
            'SC': 'Seychelles',
            'SD': 'Sudan',
            'SE': 'Sweden',
            'SG': 'Singapore',
            'SH': 'Saint Helena, Ascension and Tristan da Cunha',
            'SI': 'Slovenia',
            'SJ': 'Svalbard and Jan Mayen',
            'SK': 'Slovakia',
            'SL': 'Sierra Leone',
            'SM': 'San Marino',
            'SN': 'Senegal',
            'SO': 'Somalia',
            'SR': 'Suriname',
            'SS': 'South Sudan',
            'ST': 'Sao Tome and Principe',
            'SV': 'El Salvador',
            'SX': 'Sint Maarten (Dutch part)',
            'SY': 'Syrian Arab Republic',
            'SZ': 'Eswatini',
            'TC': 'Turks and Caicos Islands',
            'TD': 'Chad',
            'TF': 'French Southern Territories',
            'TG': 'Togo',
            'TH': 'Thailand',
            'TJ': 'Tajikistan',
            'TK': 'Tokelau',
            'TL': 'Timor-Leste',
            'TM': 'Turkmenistan',
            'TN': 'Tunisia',
            'TO': 'Tonga',
            'TR': 'Türkiye',
            'TT': 'Trinidad and Tobago',
            'TV': 'Tuvalu',
            'TW': 'Taiwan',
            'TZ': 'Tanzania, United Republic of',
            'UA': 'Ukraine',
            'UG': 'Uganda',
            'UM': 'United States Minor Outlying Islands',
            'US': 'United States',
            'UY': 'Uruguay',
            'UZ': 'Uzbekistan',
            'VA': 'Holy See',
            'VC': 'Saint Vincent and the Grenadines',
            'VE': 'Venezuela (Bolivarian Republic of)',
            'VG': 'Virgin Islands (British)',
            'VI': 'Virgin Islands (U.S.)',
            'VN': 'Viet Nam',
            'VU': 'Vanuatu',
            'WF': 'Wallis and Futuna',
            'WS': 'Samoa',
            'YE': 'Yemen',
            'YT': 'Mayotte',
            'ZA': 'South Africa',
            'ZM': 'Zambia',
            'ZW': 'Zimbabwe',
        }
        return country_names.get(country_code, country_code)
    
    def lookup_ip_country(self, ip_address: str) -> Tuple[str, str]:
        """
        Lookup country for an IP address.
        
        Returns:
            Tuple of (country_code, country_name)
        """
        if ip_address in self.ip_to_country:
            return self.ip_to_country[ip_address]
        
        try:
            # Try database lookup first
            country_info = self._lookup_ip_in_db(ip_address)
            if country_info:
                self.ip_to_country[ip_address] = country_info
                return country_info
            
            # Fall back to basic range detection
            country_info = self._detect_country_by_range(ip_address)
            self.ip_to_country[ip_address] = country_info
            return country_info
            
        except Exception as e:
            # Default to Unknown
            country_info = ('Unknown', 'Unknown')
            self.ip_to_country[ip_address] = country_info
            return country_info
    
    def _lookup_ip_in_db(self, ip_address: str) -> Optional[Tuple[str, str]]:
        """Lookup IP in local database."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT network, country_code, country_name FROM geoip')
            for row in cursor.fetchall():
                network, country_code, country_name = row
                try:
                    if ip_obj in ipaddress.ip_network(network, strict=False):
                        conn.close()
                        return (country_code, country_name or self._get_country_name(country_code))
                except:
                    continue
            
            conn.close()
            return None
            
        except Exception:
            return None
    
    def _detect_country_by_range(self, ip_address: str) -> Tuple[str, str]:
        """Basic country detection by IP range patterns."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # IPv6 handling
            if ip_obj.version == 6:
                ip_str = str(ip_obj)
                if ip_str.startswith('2001:1c'):
                    return ('NL', 'Netherlands')
                elif ip_str.startswith('2a02:a4'):
                    return ('NL', 'Netherlands')  
                elif ip_str.startswith('2a02:18'):
                    return ('NL', 'Netherlands')
                else:
                    return ('Unknown', 'Unknown')
            
            # IPv4 basic detection
            octets = str(ip_obj).split('.')
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            # Basic heuristics based on common patterns
            if first_octet in [185, 194, 195]:
                return ('EU', 'Europe')
            elif first_octet in [62, 85] and second_octet in [17, 45]:
                return ('NL', 'Netherlands')
            elif first_octet in [87, 95, 144]:
                return ('DE', 'Germany')
            elif first_octet in [8, 52, 54] or (first_octet >= 13 and first_octet <= 20):
                return ('US', 'United States')
            elif first_octet in [66, 104]:
                return ('US', 'United States')
            else:
                return ('Unknown', 'Unknown')
                
        except Exception:
            return ('Unknown', 'Unknown')
    
    def analyze_entry(self, log_entry: Dict[str, Any]) -> None:
        """Analyze a single log entry for geographic patterns."""
        ip = log_entry.get('remote_addr', '')
        if not ip:
            return
        
        # Get country info - first try from log entry, then lookup
        country_code = log_entry.get('country', '').upper()
        if not country_code or country_code == '-':
            country_code, country_name = self.lookup_ip_country(ip)
        else:
            country_name = self._get_country_name(country_code)
        
        if not country_code or country_code in ['', '-']:
            country_code = 'Unknown'
            country_name = 'Unknown'
        
        stats = self.country_stats[country_code]
        
        # Basic statistics
        stats['total_requests'] += 1
        stats['unique_ips'].add(ip)
        
        # Error tracking
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        stats['status_codes'][status] += 1
        if status >= 400:
            stats['error_requests'] += 1
        
        # Bot detection
        if log_entry.get('is_bot', False):
            stats['bot_requests'] += 1
        
        # Response time tracking
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 0:
            stats['response_times'].append(response_time)
            stats['avg_response_time'] = sum(stats['response_times']) / len(stats['response_times'])
        
        # Bandwidth tracking
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        stats['bandwidth_bytes'] += bytes_sent
        
        # Path analysis
        path = log_entry.get('path', '')
        if path:
            stats['top_paths'][path] += 1
        
        # User agent analysis
        user_agent = log_entry.get('user_agent', '')
        if user_agent:
            stats['top_user_agents'][user_agent] += 1
        
        # Hourly distribution
        timestamp = log_entry.get('timestamp')
        if timestamp:
            hour = timestamp.hour
            stats['hourly_distribution'][hour] += 1
        
        # Threat analysis
        self._analyze_threats(ip, country_code, log_entry, stats)
    
    def _analyze_threats(self, ip: str, country_code: str, log_entry: Dict[str, Any], stats: Dict[str, Any]) -> None:
        """Analyze threats from this country/IP."""
        threat_score = 0
        
        # High error rate indicates potential attacks
        error_rate = stats['error_requests'] / max(stats['total_requests'], 1)
        if error_rate > 0.1:  # More than 10% errors
            threat_score += error_rate * 10
        
        # Suspicious paths
        path = log_entry.get('path', '').lower()
        suspicious_patterns = [
            '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config',
            'sql', 'union', 'select', 'script', 'alert', 'eval'
        ]
        
        if any(pattern in path for pattern in suspicious_patterns):
            threat_score += 5
            stats['attack_attempts']['suspicious_path'] += 1
        
        # High request volume from single IP
        if stats['total_requests'] > 1000:  # High volume threshold
            threat_score += min(stats['total_requests'] / 100, 10)  # Cap at 10
        
        # Bot behavior analysis
        user_agent = log_entry.get('user_agent', '').lower()
        if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'scan']):
            if any(bad in user_agent for bad in ['hack', 'exploit', 'attack', 'inject']):
                threat_score += 8
                stats['attack_attempts']['malicious_bot'] += 1
            else:
                # Legitimate crawlers
                stats['legitimate_crawlers'].add(ip)
        
        # Update threat score and classification
        stats['threat_score'] = max(stats['threat_score'], threat_score)
        
        if threat_score > 15:
            stats['suspicious_ips'].add(ip)
            self.threat_countries.add(country_code)
        
        if stats['total_requests'] > 5000:
            self.high_volume_countries.add(country_code)
    
    def get_geographic_summary(self) -> Dict[str, Any]:
        """Get comprehensive geographic analysis summary."""
        total_countries = len(self.country_stats)
        total_requests = sum(stats['total_requests'] for stats in self.country_stats.values())
        total_unique_ips = len(set().union(*[stats['unique_ips'] for stats in self.country_stats.values()]))
        
        # Top countries by various metrics
        countries_by_requests = sorted(
            [(country, stats['total_requests']) for country, stats in self.country_stats.items()],
            key=lambda x: x[1], reverse=True
        )
        
        countries_by_threat = sorted(
            [(country, stats['threat_score']) for country, stats in self.country_stats.items()],
            key=lambda x: x[1], reverse=True
        )
        
        countries_by_errors = sorted(
            [(country, stats['error_requests']) for country, stats in self.country_stats.items()],
            key=lambda x: x[1], reverse=True
        )
        
        # Geographic threat analysis
        threat_analysis = {}
        for country_code, stats in self.country_stats.items():
            if stats['threat_score'] > 5:  # Significant threat threshold
                threat_analysis[country_code] = {
                    'country_name': self._get_country_name(country_code),
                    'threat_score': stats['threat_score'],
                    'suspicious_ips': len(stats['suspicious_ips']),
                    'attack_attempts': dict(stats['attack_attempts']),
                    'error_rate': stats['error_requests'] / max(stats['total_requests'], 1) * 100,
                    'total_requests': stats['total_requests']
                }
        
        return {
            'total_countries': total_countries,
            'total_requests': total_requests,
            'total_unique_ips': total_unique_ips,
            'threat_countries': len(self.threat_countries),
            'high_volume_countries': len(self.high_volume_countries),
            'countries_by_requests': countries_by_requests[:10],
            'countries_by_threat': countries_by_threat[:10],
            'countries_by_errors': countries_by_errors[:10],
            'threat_analysis': threat_analysis,
            'geographic_distribution': self._get_geographic_distribution()
        }
    
    def _get_geographic_distribution(self) -> Dict[str, Any]:
        """Get detailed geographic distribution analysis."""
        distribution = {}
        
        for country_code, stats in self.country_stats.items():
            if stats['total_requests'] > 0:
                distribution[country_code] = {
                    'country_name': self._get_country_name(country_code),
                    'total_requests': stats['total_requests'],
                    'unique_ips': len(stats['unique_ips']),
                    'error_rate': (stats['error_requests'] / stats['total_requests']) * 100,
                    'bot_percentage': (stats['bot_requests'] / stats['total_requests']) * 100,
                    'avg_response_time': stats['avg_response_time'],
                    'bandwidth_mb': stats['bandwidth_bytes'] / (1024 * 1024),
                    'threat_score': stats['threat_score'],
                    'top_paths': dict(stats['top_paths'].most_common(5)),
                    'hourly_peak': max(stats['hourly_distribution'].items(), key=lambda x: x[1]) if stats['hourly_distribution'] else (0, 0),
                    'status_distribution': dict(stats['status_codes'].most_common(5))
                }
        
        return distribution
    
    def get_threat_map_data(self) -> Dict[str, Any]:
        """Get data suitable for threat mapping visualization."""
        threat_map = {}
        
        for country_code, stats in self.country_stats.items():
            if stats['threat_score'] > 1:  # Any threat activity
                threat_map[country_code] = {
                    'country_name': self._get_country_name(country_code),
                    'threat_level': min(int(stats['threat_score'] / 5), 5),  # Scale 1-5
                    'threat_score': stats['threat_score'],
                    'suspicious_ips': len(stats['suspicious_ips']),
                    'attack_types': list(stats['attack_attempts'].keys()),
                    'total_attacks': sum(stats['attack_attempts'].values()),
                    'coordinates': self._get_country_coordinates(country_code)
                }
        
        return threat_map
    
    def _get_country_coordinates(self, country_code: str) -> Tuple[float, float]:
        """Get approximate coordinates for a country."""
        coordinates = {
            'US': (39.8283, -98.5795),
            'NL': (52.1326, 5.2913),
            'DE': (51.1657, 10.4515),
            'GB': (55.3781, -3.4360),
            'FR': (46.2276, 2.2137),
            'IT': (41.8719, 12.5674),
            'ES': (40.4637, -3.7492),
            'BE': (50.5039, 4.4699),
            'CA': (56.1304, -106.3468),
            'AU': (-25.2744, 133.7751),
            'JP': (36.2048, 138.2529),
            'CN': (35.8617, 104.1954),
            'IN': (20.5937, 78.9629),
            'BR': (-14.2350, -51.9253),
            'RU': (61.5240, 105.3188),
            'HK': (22.3193, 114.1694)
        }
        return coordinates.get(country_code, (0, 0))
    
    def export_geographic_report(self, output_file: str) -> None:
        """Export comprehensive geographic analysis report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_geographic_summary(),
            'threat_map': self.get_threat_map_data(),
            'detailed_analysis': self._get_geographic_distribution(),
            'recommendations': self._get_geographic_recommendations()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _get_geographic_recommendations(self) -> List[Dict[str, Any]]:
        """Generate geographic-based security recommendations."""
        recommendations = []
        
        # High threat countries
        high_threat_countries = [
            country for country, stats in self.country_stats.items()
            if stats['threat_score'] > 20
        ]
        
        if high_threat_countries:
            recommendations.append({
                'priority': 'High',
                'category': 'Geographic Blocking',
                'issue': f'High threat activity from {len(high_threat_countries)} countries',
                'recommendation': 'Consider implementing geographic blocking or additional monitoring',
                'countries': high_threat_countries,
                'details': 'These countries show significant attack patterns and suspicious activity'
            })
        
        # High volume countries with low conversion
        for country_code, stats in self.country_stats.items():
            error_rate = stats['error_requests'] / max(stats['total_requests'], 1)
            if stats['total_requests'] > 1000 and error_rate > 0.5:
                recommendations.append({
                    'priority': 'Medium',
                    'category': 'Traffic Quality',
                    'issue': f'High error rate from {country_code}',
                    'recommendation': 'Investigate traffic quality and consider rate limiting',
                    'country': country_code,
                    'error_rate': error_rate * 100,
                    'details': f'{error_rate*100:.1f}% error rate with {stats["total_requests"]} requests'
                })
        
        return recommendations
