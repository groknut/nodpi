
import json
import os

VERSION = "2.0.1"

class ProxyConfig:
    """Configuration container for proxy settings"""

    def __init__(self):

        self.host = "127.0.0.1"
        self.port = 8881
        self.out_host = None
        self.blacklist_file = "blacklist.txt"
        self.fragment_method = "random"
        self.domain_matching = "strict"
        self.log_access_file = None
        self.log_error_file = None
        self.no_blacklist = False
        self.auto_blacklist = False
        self.quiet = False


class ConfigLoader:
    """Loads configuration from command line arguments"""

    @staticmethod
    def load_from_args(args) -> ProxyConfig:

        config = ProxyConfig()
        config.host = args.host
        config.port = args.port
        config.out_host = args.out_host
        config.blacklist_file = args.blacklist
        config.fragment_method = args.fragment_method
        config.domain_matching = args.domain_matching
        config.log_access_file = args.log_access
        config.log_error_file = args.log_error
        config.no_blacklist = args.no_blacklist
        config.auto_blacklist = args.autoblacklist
        config.quiet = args.quiet
        return config

    @staticmethod
    def load_from_json(config_path: str = "config.json") -> ProxyConfig:

        if not os.path.exists(config_path):
            config_data = {}
        else:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
        config = ProxyConfig()
        config.host = config_data.get('server', {}).get('host', '127.0.0.1')
        config.port = config_data.get('server', {}).get('port', 8881)
        config.out_host = config_data.get('server', {}).get('out_host', None)
        config.fragment_method = config_data.get('fragmentation', {}).get('method', 'random')
        config.domain_matching = config_data.get('fragmentation', {}).get('domain_matching', 'strict')
        config.no_blacklist = not config_data.get('blacklist', {}).get('enabled', True)
        config.blacklist_file = config_data.get('blacklist', {}).get('file', 'blacklist.txt')
        config.auto_blacklist = config_data.get('blacklist', {}).get('auto_detect', False)
        config.log_access_file = config_data.get('log', {}).get('access_file', None)
        config.log_error_file = config_data.get('log', {}).get('error_file', None)
        config.quiet = config_data.get('log', {}).get('quiet', False)

        return config
