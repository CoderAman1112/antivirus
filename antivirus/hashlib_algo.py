import hashlib

class Hashlib:
    def get_file_hash(self, filepath):
        sha256 = hashlib.sha256()

        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    sha256.update(chunk)

            return sha256.hexdigest()
        except Exception as e:
            return f"Error: {e}"

    def check_file_hash(self, file_hash):
        with open("hashes.txt") as file:
            malware_hashes = file.read()

        if file_hash in malware_hashes:
            return True
        else:
            return False
