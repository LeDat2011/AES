

# S-box tiêu chuẩn (phục vụ cho SubBytes)
S_BOX = [
    # 0     1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Rcon – hằng số vòng cho key expansion
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
]


# Các hàm AES tự triển khai (sub_bytes, shift_rows, mix_columns, add_round_key, key_expansion, encrypt, decrypt)
class AES:
    """
    Lớp triển khai thuật toán mã hóa AES
    Hỗ trợ các mode: ECB và CBC
    Độ dài khóa: 128-bit, 192-bit, 256-bit
    """

    def __init__(self, key: bytes):
        """
        Khởi tạo đối tượng AES với khóa được cung cấp
        Args:
            key (bytes): Khóa mã hóa (16, 24 hoặc 32 bytes)
        """
        # Kiểm tra độ dài khóa hợp lệ
        valid_key_lengths = {16: "AES-128", 24: "AES-192", 32: "AES-256"}
        if len(key) not in valid_key_lengths:
            raise ValueError(f"Độ dài khóa không hợp lệ. Phải là {', '.join(valid_key_lengths.values())}")

        self.key = key
        self.Nk = len(key) // 4  # Số từ 32-bit trong khóa
        self.Nb = 4  # Số từ 32-bit trong block
        self.Nr = {16: 10, 24: 12, 32: 14}[len(key)]  # Số vòng lặp
        self.w = self.key_expansion(key)  # Mở rộng khóa

    def sub_bytes(self, state):
        return [S_BOX[b] for b in state]

    def shift_rows(self, state):
        """Hàm ShiftRows: Dịch chuyển các dòng trong khối AES"""
        return [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]

    def inv_shift_rows(self, state):
        """Hàm inv_shift_rows: Đảo ngược ShiftRows trong quá trình giải mã"""
        return [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]
        ]

    def mix_columns(self, state):
        """Hàm MixColumns: Trộn các cột trong khối AES"""

        def xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

        def mix_single_column(column):
            t = column[0] ^ column[1] ^ column[2] ^ column[3]
            u = column[0]
            column[0] ^= t ^ xtime(column[0] ^ column[1])
            column[1] ^= t ^ xtime(column[1] ^ column[2])
            column[2] ^= t ^ xtime(column[2] ^ column[3])
            column[3] ^= t ^ xtime(column[3] ^ u)

        for i in range(0, 16, 4):
            col = state[i:i + 4]
            mix_single_column(col)
            state[i:i + 4] = col
        return state

    def inv_mix_columns(self, state):
        """Hàm inv_mix_columns: Đảo ngược MixColumns trong quá trình giải mã"""

        def mul(a, b):
            p = 0
            for i in range(8):
                if b & 1:
                    p ^= a
                hi_bit = a & 0x80
                a = (a << 1) & 0xFF
                if hi_bit:
                    a ^= 0x1B
                b >>= 1
            return p

        for i in range(0, 16, 4):
            a = state[i:i + 4]
            state[i + 0] = mul(a[0], 0x0e) ^ mul(a[1], 0x0b) ^ mul(a[2], 0x0d) ^ mul(a[3], 0x09)
            state[i + 1] = mul(a[0], 0x09) ^ mul(a[1], 0x0e) ^ mul(a[2], 0x0b) ^ mul(a[3], 0x0d)
            state[i + 2] = mul(a[0], 0x0d) ^ mul(a[1], 0x09) ^ mul(a[2], 0x0e) ^ mul(a[3], 0x0b)
            state[i + 3] = mul(a[0], 0x0b) ^ mul(a[1], 0x0d) ^ mul(a[2], 0x09) ^ mul(a[3], 0x0e)
        return state

    def add_round_key(self, state, round_key):
        """Hàm AddRoundKey: Áp dụng khóa vào trạng thái"""
        return [s ^ rk for s, rk in zip(state, round_key)]

    def key_expansion(self, key):
        """Hàm key_expansion: Mở rộng khóa cho AES"""

        def sub_word(word):
            return [S_BOX[b] for b in word]

        def rot_word(word):
            return word[1:] + word[:1]

        w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
        i = self.Nk
        while len(w) < (self.Nb * (self.Nr + 1)):
            temp = w[-1]
            if i % self.Nk == 0:
                temp = [a ^ b for a, b in zip(sub_word(rot_word(temp)), [RCON[i // self.Nk - 1], 0, 0, 0])]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = sub_word(temp)
            w.append([a ^ b for a, b in zip(w[i - self.Nk], temp)])
            i += 1
        return [b for word in w for b in word]

    def pad(self, data):
        """PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data):
        """PKCS7 unpadding"""
        padding_length = data[-1]
        if padding_length > 16:
            raise ValueError("Padding không hợp lệ")
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Padding không hợp lệ")
        return data[:-padding_length]

    def encrypt_block(self, block):
        """Mã hóa một block 16 byte"""
        state = list(block)

        # Vòng 0: AddRoundKey
        state = self.add_round_key(state, self.w[:16])

        # Vòng 1 -> Nr-1
        for rnd in range(1, self.Nr):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.w[rnd * 16:(rnd + 1) * 16])

        # Vòng cuối
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.w[self.Nr * 16:(self.Nr + 1) * 16])

        return bytes(state)

    def decrypt_block(self, block):
        """Giải mã một block 16 byte"""
        state = list(block)

        # Vòng cuối (ngược)
        state = self.add_round_key(state, self.w[self.Nr * 16:(self.Nr + 1) * 16])
        state = self.inv_shift_rows(state)
        state = [S_BOX.index(b) for b in state]  # inv_sub_bytes

        # Vòng Nr-1 -> 1 (ngược)
        for rnd in range(self.Nr - 1, 0, -1):
            state = self.add_round_key(state, self.w[rnd * 16:(rnd + 1) * 16])
            state = self.inv_mix_columns(state)
            state = self.inv_shift_rows(state)
            state = [S_BOX.index(b) for b in state]  # inv_sub_bytes

        # Vòng 0 (ngược)
        state = self.add_round_key(state, self.w[:16])

        return bytes(state)

    def encrypt_ecb(self, data: bytes) -> bytes:
        """
        Mã hóa dữ liệu sử dụng mode ECB (Electronic CodeBook)
        Mỗi block được mã hóa độc lập
        """
        data = self.pad(data)
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        return b''.join(self.encrypt_block(block) for block in blocks)

    def decrypt_ecb(self, data: bytes) -> bytes:
        """Giải mã dữ liệu đã mã hóa bằng mode ECB"""
        if len(data) % 16 != 0:
            raise ValueError("Dữ liệu mã hóa phải có độ dài là bội số của 16")

        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        decrypted = b''.join(self.decrypt_block(block) for block in blocks)
        return self.unpad(decrypted)

    def encrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """
        Mã hóa dữ liệu sử dụng mode CBC (Cipher Block Chaining)
        Mỗi block được XOR với block mã hóa trước đó
        """
        if len(iv) != 16:
            raise ValueError("IV phải có độ dài 16 bytes")

        data = self.pad(data)
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        encrypted_blocks = []
        previous = iv

        for block in blocks:
            xored = bytes(a ^ b for a, b in zip(block, previous))
            encrypted = self.encrypt_block(xored)
            encrypted_blocks.append(encrypted)
            previous = encrypted

        return b''.join(encrypted_blocks)

    def decrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """Giải mã dữ liệu đã mã hóa bằng mode CBC"""
        if len(data) % 16 != 0:
            raise ValueError("Dữ liệu mã hóa phải có độ dài là bội số của 16")

        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        decrypted_blocks = []
        previous = iv

        for block in blocks:
            decrypted = self.decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, previous))
            decrypted_blocks.append(xored)
            previous = block

        decrypted_data = b''.join(decrypted_blocks)
        return self.unpad(decrypted_data)

    def encrypt(self, data):
        """Mã hóa dữ liệu"""
        data = self.pad(data)
        return b''.join(self.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))

    def decrypt(self, data):
        """Giải mã dữ liệu"""
        return self.unpad(b''.join(self.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16)))

