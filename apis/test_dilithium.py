import unittest
import pickle
from dilithium import Dilithium

class TestDilithium(unittest.TestCase):
    def setUp(self):
        self.dilithium = Dilithium()

    def test_init(self):
        self.assertIsNotNone(self.dilithium.pk)
        self.assertIsNotNone(self.dilithium.sk)

    

    import pickle

    def test_sign_and_verify(self):
        message = b"ghassan"
        signature = self.dilithium.sign(message)

        # Convertir la signature en chaîne de caractères
        signature_str = pickle.dumps(signature)

        # Reconvertissez la chaîne de caractères en tuple
        signature_tuple = pickle.loads(signature_str)

        # Vérifier la signature
        self.assertTrue(self.dilithium.verify(message, signature_tuple))
        

if __name__ == '__main__':
    unittest.main()