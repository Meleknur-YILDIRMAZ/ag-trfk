import os

class ListManager:
    def __init__(self, whitelist_path, blacklist_path):
        self.whitelist_path = whitelist_path
        self.blacklist_path = blacklist_path
        self.whitelist = self._load_list(self.whitelist_path)
        self.blacklist = self._load_list(self.blacklist_path)

    def _load_list(self, path):
        if not os.path.exists(path):
            return set()
        with open(path, 'r', encoding='utf-8') as f:
            return set(line.strip() for line in f if line.strip())

    def _save_list(self, path, data):
        with open(path, 'w', encoding='utf-8') as f:
            for item in sorted(list(data)):
                f.write(f"{item}\n")

    def add(self, list_type, ip):
        if list_type == "whitelist":
            self.whitelist.add(ip)
            self._save_list(self.whitelist_path, self.whitelist)
        elif list_type == "blacklist":
            self.blacklist.add(ip)
            self._save_list(self.blacklist_path, self.blacklist)

    def remove(self, list_type, ip):
        if list_type == "whitelist":
            self.whitelist.discard(ip)
            self._save_list(self.whitelist_path, self.whitelist)
        elif list_type == "blacklist":
            self.blacklist.discard(ip)
            self._save_list(self.blacklist_path, self.blacklist)

    def is_whitelisted(self, ip):
        return ip in self.whitelist

    def is_blacklisted(self, ip):
        return ip in self.blacklist
