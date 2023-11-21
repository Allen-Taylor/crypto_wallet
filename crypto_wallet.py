from mnemonic import Mnemonic
from web3 import Web3
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Crypto_Wallet:
    DEFAULT_FILE_NAME = 'wallet.json'
    PROVIDER_URL = 'https://goerli.infura.io/v3/9c6f33d4175a496c8a4f1b089cddefcc'

    def __init__(self, language="english"):
        # Initialize a Crypto_Wallet instance.
        self.mnemo = Mnemonic(language)
        self.w3 = Web3(Web3.HTTPProvider(self.PROVIDER_URL))
        self.account = None
        self.words = None

    def create_wallet(self, strength=256, filename=DEFAULT_FILE_NAME):
        # Create a new Ethereum wallet and save it to a file.
        self.words = self.mnemo.generate(strength=strength)
        seed = self.mnemo.to_seed(self.words)
        private_key_bytes = seed[:32]
        private_key_hex = self.w3.to_hex(private_key_bytes)
        account = self.w3.eth.account.from_key(private_key_hex)
        self.account = account
        self.words = self.words
        self.save_wallet_to_file(filename)
        print('Address:', self.account.address)
        print('Private Key:', private_key_hex)
        print('Mnemonic:', self.words)

    @staticmethod
    def get_fernet_key(password: str) -> bytes:
        # Generate a Fernet encryption key from a password using PBKDF2HMAC.
        salt = b"you_can_have_static_salt"
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_data(data: str, password: str) -> bytes:
        # Encrypt data using Fernet encryption.
        key = Crypto_Wallet.get_fernet_key(password)
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data: bytes, password: str) -> str:
        # Decrypt data using Fernet decryption.
        key = Crypto_Wallet.get_fernet_key(password)
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data

    def save_wallet_to_file(self, filename):
        # Save wallet information to a file, encrypting it with a user-provided password.
        if not self.account or not self.words:
            raise ValueError("No account or mnemonic words loaded or created.")

        while True:
            password = input("Enter a strong password to encrypt the wallet: ")

            if (len(password) < 12 or
                not any(char.isupper() for char in password) or
                not any(char.islower() for char in password) or
                not any(char.isdigit() for char in password) or
                not any(char in "!@#$%^&*()_+-=[]{}|;:'\",.<>?/" for char in password)):
                print("Password must be at least 12 characters in length with at least 1 special character, number, uppercase and lowercase letter")
            else:
                confirm_passphrase = input("Confirm the password: ")

                if confirm_passphrase != password:
                    print("Passwords do not match. Please re-enter the password.")
                else:
                    break

        data = {'address': self.account.address, 'private_key': self.w3.to_hex(self.account.key), 'mnemonic': self.words}
        encrypted_data = self.encrypt_data(json.dumps(data), password)
        with open(filename, 'wb') as file:
            file.write(encrypted_data)
            return

    def load_wallet_from_file(self, filename):
        # Load a wallet from an encrypted file, prompting the user for the decryption password.
        while True:
            try:
                if not os.path.exists(filename):
                    raise FileNotFoundError(f"File '{filename}' not found!")

                password = input("Enter the password to decrypt the wallet file: ")

                with open(filename, "rb") as file:
                    encrypted_data = file.read()
                    data_str = self.decrypt_data(encrypted_data, password)

                data = json.loads(data_str)
                self.account = self.w3.eth.account.from_key(data["private_key"])
                self.words = data["mnemonic"]

                print("Wallet loaded successfully.")
                break

            except FileNotFoundError as e:
                print(e)
                return

            except Exception as e:
                print(f"Incorrect password or corrupted file. Could not load wallet {e}")
                retry = input("Do you want to try again? (y/n)? ").lower()
                if retry != "y":
                    return

    def get_balance(self):
        # Get the Ethereum balance of the currently loaded wallet.
        if not self.account:
            print("No account loaded or created.")
            return
        return self.w3.eth.get_balance(self.account.address)

    def get_address(self):
        # Get the Ethereum address of the currently loaded wallet.
        if not self.account:
            print("No account loaded or created.")
            return
        return self.account.address

    def transfer_eth(self, receiver_address):
        # Transfer Ether from the currently loaded wallet to the specified recipient.
        if not self.account:
            print("Please create a new wallet or import a wallet.")
            return
        print("Sender Account", self.account.address)
        sender_balance_wei = self.get_balance()
        sender_balance_eth = self.w3.from_wei(sender_balance_wei, 'ether')
        print(f"Sender's ETH Balance: {sender_balance_eth} ETH")
        amount_eth = float(input("Enter the amount of ETH to send: "))
        if amount_eth <= sender_balance_eth:
            amount_in_wei = self.w3.to_wei(amount_eth, 'ether')
            gas_estimate = self.w3.eth.estimate_gas({
                'to': receiver_address,
                'value': amount_in_wei,
            })

            transaction = {
                'to': receiver_address,
                'value': amount_in_wei,
                'gas': gas_estimate,
                'gasPrice': self.w3.to_wei('5', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
            }

            signed_transaction = self.w3.eth.account.sign_transaction(transaction, self.account.key)
            transaction_hash = self.w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
            print(f"Transaction Hash: {transaction_hash.hex()}")
        else:
            print("Insufficient balance.")

    def import_wallet(self, mnemonic, filename=DEFAULT_FILE_NAME):
        # Import a wallet using a mnemonic and save it to a file.
        if not self.mnemo.check(mnemonic):
            print("Invalid mnemonic phrase.")
            return

        seed = self.mnemo.to_seed(mnemonic)
        private_key_bytes = seed[:32]
        private_key_hex = self.w3.to_hex(private_key_bytes)
        account = self.w3.eth.account.from_key(private_key_hex)
        self.account = account
        self.words = mnemonic
        self.save_wallet_to_file(filename)
        print('Address:', self.account.address)
        print('Private Key:', private_key_hex)
        print('Mnemonic:', self.words)

    def show_menu(self):
        # Display a menu for interacting with the Ethereum wallet.
        while True:
            print("Ethereum Wallet Menu:")
            print("1. Create New Wallet")
            print("2. Load Wallet")
            print("3. Get Wallet Address")
            print("4. Get Wallet Balance")
            print("5. Transfer Token(s)")
            print("6. Import Wallet")
            print("7. Exit Program")

            selection = input("Enter your selection: ")

            if selection == '1':
                self.create_wallet()
            elif selection == "2":
                filename = input("Enter the wallet file name: ")
                self.load_wallet_from_file(filename)
            elif selection == '3':
                print("Wallet Address:", self.get_address())
            elif selection == '4':
                balance = self.get_balance()
                if balance is not None:
                    print("Wallet Balance:", self.w3.from_wei(balance, 'ether'), "ETH")
            elif selection == '5':
                receiver_address = input("Enter the recipient's Ethereum address: ")
                self.transfer_eth(receiver_address)
            elif selection == '6':
                mnemonic = input("Enter the mnemonic: ")
                self.import_wallet(mnemonic)
            elif selection == '7':
                print("Thank you for using our program")
                break
            else:
                print("Invalid selection. Please select a proper option.")

if __name__ == "__main__":
    wallet = Crypto_Wallet()
    wallet.show_menu()