class GenerateKeyResponse:
    def __init__(self, private, public, modulus):
        self.private = private
        self.public = public
        self.modulus = modulus
