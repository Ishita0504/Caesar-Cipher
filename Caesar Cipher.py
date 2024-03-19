import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget, QTextEdit, QMessageBox
def encrypt(text, key):
    result = ""
    message = text.upper()
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""

    for letter in message:
        if letter in alpha:  # if the letter is actually a letter
            # find the corresponding ciphertext letter in the alphabet
            letter_index = (alpha.find(letter) + key) % len(alpha)

            result = result + alpha[letter_index]
        else:
            result = result + letter

    return result
def decrypt(text,key):
     message = text.upper()
     alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
     result = ""

     for letter in message:
        if letter in alpha: #if the letter is actually a letter
            #find the corresponding ciphertext letter in the alphabet
            letter_index = (alpha.find(letter) - key) % len(alpha)

            result = result + alpha[letter_index]
        else:
            result = result + letter

     return result

class CaesarCipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Caesar Cipher')
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        tab_widget = QTabWidget()
        encryption_tab = QWidget()
        decryption_tab = QWidget()

        tab_widget.addTab(encryption_tab, "Encryption")
        tab_widget.addTab(decryption_tab, "Decryption")

        # Encryption Tab
        encryption_layout = QVBoxLayout()
        self.plain_text_edit_enc = QTextEdit()
        self.cipher_text_edit_enc = QTextEdit()
        self.shift_edit_enc = QLineEdit()
        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt)
        encryption_layout.addWidget(QLabel("Plain Text:"))
        encryption_layout.addWidget(self.plain_text_edit_enc)
        encryption_layout.addWidget(QLabel("Shift:"))
        encryption_layout.addWidget(self.shift_edit_enc)
        encryption_layout.addWidget(self.encrypt_button)
        encryption_layout.addWidget(QLabel("Cipher Text:"))
        encryption_layout.addWidget(self.cipher_text_edit_enc)
        encryption_tab.setLayout(encryption_layout)

        # Decryption Tab
        decryption_layout = QVBoxLayout()
        self.cipher_text_edit_dec = QTextEdit()
        self.plain_text_edit_dec = QTextEdit()
        self.shift_edit_dec = QLineEdit()
        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt)
        decryption_layout.addWidget(QLabel("Cipher Text:"))
        decryption_layout.addWidget(self.cipher_text_edit_dec)
        decryption_layout.addWidget(QLabel("Shift:"))
        decryption_layout.addWidget(self.shift_edit_dec)
        decryption_layout.addWidget(self.decrypt_button)
        decryption_layout.addWidget(QLabel("Plain Text:"))
        decryption_layout.addWidget(self.plain_text_edit_dec)
        decryption_tab.setLayout(decryption_layout)

        layout.addWidget(tab_widget)
        self.setLayout(layout)

    def encrypt(self):
        plain_text = self.plain_text_edit_enc.toPlainText()
        try:
            shift = int(self.shift_edit_enc.text())
            cipher_text = encrypt(plain_text, shift)
            self.cipher_text_edit_enc.setPlainText(cipher_text)
        except ValueError:
            self.show_error_message("Shift must be an integer.")

    def decrypt(self):
        cipher_text = self.cipher_text_edit_dec.toPlainText()
        try:
            shift = int(self.shift_edit_dec.text())
            plain_text = decrypt(cipher_text, shift)
            self.plain_text_edit_dec.setPlainText(plain_text)
        except ValueError:
            self.show_error_message("Shift must be an integer.")

    def show_error_message(self, message):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setWindowTitle("Error")
        msg_box.setText(message)
        msg_box.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CaesarCipherApp()
    window.show()
    sys.exit(app.exec_())



