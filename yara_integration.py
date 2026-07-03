import yara

class YaraIntegration:

    def __init__(self):
        rule = r"""
        rule MalwareDetection
        {
            strings:
                $a = "malware"
                $b = "virus"
                $c = "malicious_payload"

            condition:
                any of them
        }

        rule PE_File
        {
            condition:
                uint16(0) == 0x5A4D
        }

        rule Hex_Pattern
        {
            strings:
                $hex = {4D 5A 90 00}
            condition:
                $hex
        }

        rule Base64
        {
            strings:
                $a = /[A-Za-z0-9+\/]{40,}={0,2}/
            condition:
                $a
        }

        rule Many_Indicators
        {
            strings:
                $a = "VirtualAlloc"
                $b = "LoadLibraryA"
                $c = "WriteProcessMemory"
                $d = "CreateRemoteThread"
            condition:
                2 of them
        }

        rule ASCII_Wide
        {
            strings:
                $a = "powershell" ascii wide
            condition:
                $a
        }

        rule Injection_APIs
        {
            strings:
                $a = "VirtualAlloc"
                $b = "WriteProcessMemory"
                $c = "CreateRemoteThread"
            condition:
                all of them
}
        """

        self.rules = yara.compile(source=rule)

    def yaraApply(self, unchecked_file):
        try:
            with open(unchecked_file, "rb") as file:
                file_data = file.read()

            matches = self.rules.match(data=file_data)

            if matches:
                return True
            else:
                return False
        except(PermissionError, FileNotFoundError, OSError):
            return False

# yi = YaraIntegration()

# yi.yaraApply("virus.txt")