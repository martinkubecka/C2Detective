class AnalystProfile:
    def __init__(self, api_keys, arguments):
        self.api_keys = api_keys
        self.arguments = arguments

    def test(self):
        print(self.api_keys)
        print(self.arguments)