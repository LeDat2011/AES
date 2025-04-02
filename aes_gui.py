import os
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from datetime import datetime
import time
from aes_core import AES
import base64


# Giao diện Tkinter cho ứng dụng mã hóa AES (Đã có sẵn trong mã trước đó)
class AESEncryptionApp:
    """
    Giao diện đồ họa cho ứng dụng mã hóa AES
    Hỗ trợ mã hóa/giải mã file với các mode ECB và CBC
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Ứng dụng Mã hóa và Giải mã AES")
        self.setup_gui()

    def setup_gui(self):
        """Thiết lập giao diện người dùng"""
        self.root.geometry("900x700")
        self.root.configure(padx=20, pady=20)

        # 1. Frame chọn file (đầu tiên)
        self.create_file_frame()

        # 2. Frame chọn độ dài khóa (thứ hai)
        self.create_key_length_frame()

        # 3. Frame chọn mode mã hóa (thứ ba)
        self.create_mode_frame()

        # 4. Frame cài đặt khóa (thứ tư)
        self.create_key_frame()

        # 5. Frame điều khiển (thứ năm)
        self.create_control_frame()

        # 6. Frame kết quả (cuối cùng)
        self.create_result_frame()

    def create_file_frame(self):
        """Frame chọn file đầu vào/ra"""
        file_frame = ttk.LabelFrame(self.root, text="1. Chọn File")
        file_frame.pack(fill=tk.X, padx=10, pady=5)

        # File đầu vào
        input_frame = ttk.Frame(file_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(input_frame, text="File đầu vào:", width=12).pack(side=tk.LEFT)
        self.input_file_entry = ttk.Entry(input_frame)
        self.input_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_input_button = ttk.Button(input_frame, text="Duyệt...",
                                              command=self.browse_input_file)
        self.browse_input_button.pack(side=tk.LEFT)

        # File đầu ra
        output_frame = ttk.Frame(file_frame)
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(output_frame, text="File đầu ra:", width=12).pack(side=tk.LEFT)
        self.output_file_entry = ttk.Entry(output_frame)
        self.output_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_output_button = ttk.Button(output_frame, text="Duyệt...",
                                               command=self.browse_output_file)
        self.browse_output_button.pack(side=tk.LEFT)

    def create_key_length_frame(self):
        """Frame chọn độ dài khóa"""
        key_length_frame = ttk.LabelFrame(self.root, text="2. Chọn độ dài khóa")
        key_length_frame.pack(fill=tk.X, padx=10, pady=5)

        self.key_length_var = tk.StringVar(value="256")
        for length, text in [("128", "AES-128 (128 bit)"),
                             ("192", "AES-192 (192 bit)"),
                             ("256", "AES-256 (256 bit)")]:
            ttk.Radiobutton(key_length_frame, text=text,
                            variable=self.key_length_var,
                            value=length).pack(side=tk.LEFT, padx=20, pady=5)

    def create_mode_frame(self):
        """Frame chọn mode mã hóa"""
        mode_frame = ttk.LabelFrame(self.root, text="3. Chọn mode mã hóa")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)

        self.mode_var = tk.StringVar(value="CBC")
        ttk.Radiobutton(mode_frame, text="ECB Mode (Không cần IV)",
                        variable=self.mode_var, value="ECB",
                        command=self.toggle_iv_visibility).pack(side=tk.LEFT, padx=20, pady=5)
        ttk.Radiobutton(mode_frame, text="CBC Mode (Cần IV)",
                        variable=self.mode_var, value="CBC",
                        command=self.toggle_iv_visibility).pack(side=tk.LEFT, padx=20, pady=5)

    def create_key_frame(self):
        """Frame cài đặt khóa"""
        key_frame = ttk.LabelFrame(self.root, text="4. Cài đặt khóa")
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        # Frame định dạng khóa
        format_frame = ttk.Frame(key_frame)
        format_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(format_frame, text="Tạo khóa mới",
                   command=self.generate_key_iv).pack(side=tk.LEFT, padx=5)
        ttk.Label(format_frame, text="hoặc chọn định dạng:").pack(side=tk.LEFT, padx=5)

        self.key_format = tk.StringVar(value="ascii")
        for fmt, text in [("ascii", "ASCII Text"),
                          ("base64", "Base64"),
                          ("hex", "Hex")]:
            ttk.Radiobutton(format_frame, text=text,
                            variable=self.key_format,
                            value=fmt).pack(side=tk.LEFT, padx=10)

        # Frame nhập khóa
        key_input_frame = ttk.Frame(key_frame)
        key_input_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(key_input_frame, text="Nhập khóa:", width=12).pack(side=tk.LEFT)
        self.key_entry = ttk.Entry(key_input_frame)
        self.key_entry.pack(fill=tk.X, expand=True, padx=5)

        # Frame nhập IV (cho CBC)
        self.iv_frame = ttk.Frame(key_frame)
        self.iv_frame.pack(fill=tk.X, padx=5, pady=5)
        self.iv_label = ttk.Label(self.iv_frame, text="Nhập IV:", width=12)
        self.iv_label.pack(side=tk.LEFT)
        self.iv_entry = ttk.Entry(self.iv_frame)
        self.iv_entry.pack(fill=tk.X, expand=True, padx=5)

    def create_control_frame(self):
        """Frame điều khiển"""
        control_frame = ttk.LabelFrame(self.root, text="5. Thao tác")
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        button_frame = ttk.Frame(control_frame)
        button_frame.pack(padx=5, pady=5)

        self.encrypt_button = ttk.Button(button_frame, text="Mã hóa File",
                                         command=self.encrypt_file_gui)
        self.encrypt_button.pack(side=tk.LEFT, padx=10)

        self.decrypt_button = ttk.Button(button_frame, text="Giải mã File",
                                         command=self.decrypt_file_gui)
        self.decrypt_button.pack(side=tk.LEFT, padx=10)

    def create_result_frame(self):
        """Frame kết quả"""
        result_frame = ttk.LabelFrame(self.root, text="6. Kết quả")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Notebook với các tab
        self.result_notebook = ttk.Notebook(result_frame)
        self.result_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tab thông tin
        info_frame = ttk.Frame(self.result_notebook)
        self.result_notebook.add(info_frame, text="Thông tin")
        self.result_text = tk.Text(info_frame, wrap=tk.WORD, height=10)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Tab dữ liệu hex
        hex_frame = ttk.Frame(self.result_notebook)
        self.result_notebook.add(hex_frame, text="Dữ liệu Hex")
        self.hex_text = tk.Text(hex_frame, wrap=tk.WORD, height=10)
        self.hex_text.pack(fill=tk.BOTH, expand=True)

        # Thanh trạng thái
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_var = tk.StringVar(value="Sẵn sàng")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var,
                               relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame,
                                            variable=self.progress_var,
                                            maximum=100, length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

    def browse_input_file(self):
        """Chọn file đầu vào"""
        filename = filedialog.askopenfilename(
            title="Chọn File Đầu Vào",
            filetypes=[("Tất cả file", "*.*")]
        )
        if filename:
            self.input_file_entry.delete(0, tk.END)
            self.input_file_entry.insert(0, filename)

            # Tự động đề xuất tên file đầu ra
            self.output_file_entry.delete(0, tk.END)
            base_name, ext = os.path.splitext(filename)
            if ext.lower() == '.enc':
                self.output_file_entry.insert(0, base_name + "_decrypted")
            else:
                self.output_file_entry.insert(0, filename + ".enc")

    def browse_output_file(self):
        """Chọn file đầu ra"""
        filename = filedialog.asksaveasfilename(
            title="Chọn File Đầu Ra",
            filetypes=[("Tất cả file", "*.*")]
        )
        if filename:
            self.output_file_entry.delete(0, tk.END)
            self.output_file_entry.insert(0, filename)

    def toggle_iv_visibility(self):
        """Ẩn/hiện trường IV dựa trên mode được chọn"""
        if self.mode_var.get() == "ECB":
            self.iv_frame.pack_forget()  # Ẩn toàn bộ frame IV
        else:
            self.iv_frame.pack(fill=tk.X, padx=5, pady=5)  # Hiện frame IV

    def generate_key_iv(self):
        """Tạo key và IV mới"""
        try:
            key_length = int(self.key_length_var.get()) // 8
            key_format = self.key_format.get()

            if key_format == "ascii":
                # Tạo key ASCII từ các ký tự cho phép
                import string
                allowed_chars = string.ascii_letters + string.digits + string.punctuation
                import random
                self.key = ''.join(random.choice(allowed_chars)
                                   for _ in range(key_length)).encode('utf-8')
                key_display = self.key.decode('utf-8')
            else:
                # Tạo key ngẫu nhiên cho Base64 và Hex
                self.key = os.urandom(key_length)
                if key_format == "base64":
                    key_display = base64.b64encode(self.key).decode()
                else:  # hex
                    key_display = self.key.hex()

            # Tạo IV mới (luôn dạng Base64)
            self.iv = os.urandom(16)
            iv_display = base64.b64encode(self.iv).decode()

            # Cập nhật giao diện
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key_display)

            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, iv_display)

            # Hiển thị thông tin chi tiết
            details = (
                f"TẠO KHÓA MỚI THÀNH CÔNG\n"
                f"{'=' * 30}\n"
                f"Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Định dạng: {key_format.upper()}\n"
                f"Độ dài khóa: AES-{key_length * 8}\n\n"
                f"Key:\n"
                f"▸ ASCII: {self.safe_decode(self.key)}\n"
                f"▸ Hex: {self.key.hex()}\n"
                f"▸ Base64: {base64.b64encode(self.key).decode()}\n\n"
                f"IV:\n"
                f"▸ Base64: {iv_display}\n"
                f"▸ Hex: {self.iv.hex()}\n"
                f"{'=' * 30}\n"
            )
            self.log_message(details)

        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi tạo khóa: {str(e)}")

    def safe_decode(self, data):
        """Giải mã an toàn bytes sang ASCII, thay thế ký tự không đọc được"""
        try:
            return data.decode('utf-8')
        except:
            return '[Không thể hiển thị dạng ASCII]'

    def log_message(self, message):
        """Ghi log và hiển thị kết quả"""
        # Hiển thị trong tab thông tin
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, message)

        # Ghi vào file log
        try:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{current_time}]\n{message}\n{'=' * 50}\n"

            with open("D:/KMA/AES/log.txt", "a", encoding="utf-8") as log_file:
                log_file.write(log_entry)
        except Exception as e:
            print(f"Lỗi khi ghi log: {str(e)}")

    def encrypt_file_gui(self):
        """Xử lý mã hóa file từ GUI"""
        self.disable_controls()
        try:
            if not self.validate_paths():
                return

            input_file = self.input_file_entry.get().strip()
            output_file = self.output_file_entry.get().strip()
            key, _ = self.get_key_iv_from_entries()  # Chỉ lấy key

            if key is None:
                return

            # Tạo IV mới cho mỗi lần mã hóa
            new_iv = os.urandom(16)

            # Cập nhật IV trong giao diện
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, base64.b64encode(new_iv).decode())

            # Cập nhật trạng thái
            self.status_var.set("Đang mã hóa...")
            self.root.update_idletasks()

            # Bắt đầu mã hóa và tính thời gian
            start_time = time.time()
            mode = self.mode_var.get()
            key_length = int(self.key_length_var.get())

            # Thực hiện mã hóa với IV mới
            self.encrypt_file(input_file, output_file, key, new_iv)

            # Tính toán thông số
            encryption_time = time.time() - start_time
            if encryption_time == 0:
                encryption_time = 0.0001

            input_size = os.path.getsize(input_file)
            output_size = os.path.getsize(output_file)
            throughput = input_size / encryption_time / 1024 / 1024  # MB/s

            # Tạo thông báo kết quả chi tiết
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result_message = (
                f"KẾT QUẢ MÃ HÓA\n"
                f"{'=' * 30}\n"
                f"Thời gian: {current_time}\n"
                f"Mode: {mode}\n"
                f"Độ dài khóa: AES-{key_length}\n"
                f"IV mới: {new_iv.hex()}\n\n"  # Thêm thông tin IV mới
                f"File gốc: {input_file}\n"
                f"↳ Kích thước: {input_size:,} bytes\n\n"
                f"File mã hóa: {output_file}\n"
                f"↳ Kích thước: {output_size:,} bytes\n\n"
                f"Hiệu năng:\n"
                f"↳ Thời gian mã hóa: {encryption_time:.6f} giây\n"
                f"↳ Tốc độ xử lý: {throughput:.2f} MB/giây\n"
                f"{'=' * 30}\n"
                f"Trạng thái: Mã hóa thành công!"
            )

            # Ghi log và hiển thị kết quả
            self.log_message(result_message)
            self.status_var.set("Mã hóa hoàn tất")
            self.progress_var.set(100)

        except Exception as e:
            error_message = f"Lỗi khi mã hóa file: {str(e)}"
            messagebox.showerror("Lỗi", error_message)
            self.status_var.set("Lỗi khi mã hóa")
            self.log_message(f"LỖI: {error_message}")
        finally:
            self.enable_controls()

    def disable_controls(self):
        """Disable các control khi đang xử lý"""
        for widget in [self.encrypt_button, self.decrypt_button,
                       self.browse_input_button, self.browse_output_button]:
            widget.configure(state='disabled')

    def enable_controls(self):
        """Enable lại các control sau khi xử lý xong"""
        for widget in [self.encrypt_button, self.decrypt_button,
                       self.browse_input_button, self.browse_output_button]:
            widget.configure(state='normal')

    def decrypt_file_gui(self):
        """Xử lý giải mã file từ GUI"""
        self.disable_controls()
        try:
            input_file = self.input_file_entry.get().strip()
            output_file = self.output_file_entry.get().strip()
            key, iv = self.get_key_iv_from_entries()

            if key is None or iv is None:
                return

            # Cập nhật trạng thái
            self.status_var.set("Đang giải mã...")
            self.root.update_idletasks()

            # Bắt đầu giải mã và tính thời gian
            start_time = time.time()
            mode = self.mode_var.get()
            key_length = int(self.key_length_var.get())

            # Thực hiện giải mã
            self.decrypt_file(input_file, output_file, key)

            # Tính toán thông số
            decryption_time = time.time() - start_time
            if decryption_time == 0:
                decryption_time = 0.0001

            input_size = os.path.getsize(input_file)
            output_size = os.path.getsize(output_file)
            throughput = output_size / decryption_time / 1024 / 1024  # MB/s

            # Tạo thông báo kết quả chi tiết
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result_message = (
                f"KẾT QUẢ GIẢI MÃ\n"
                f"{'=' * 30}\n"
                f"Thời gian: {current_time}\n"
                f"Mode: {mode}\n"
                f"Độ dài khóa: AES-{key_length}\n\n"
                f"File mã hóa: {input_file}\n"
                f"↳ Kích thước: {input_size:,} bytes\n\n"
                f"File giải mã: {output_file}\n"
                f"↳ Kích thước: {output_size:,} bytes\n\n"
                f"Hiệu năng:\n"
                f"↳ Thời gian giải mã: {decryption_time:.6f} giây\n"
                f"↳ Tốc độ xử lý: {throughput:.2f} MB/giây\n"
                f"{'=' * 30}\n"
                f"Trạng thái: Giải mã thành công!"
            )

            # Ghi log và hiển thị kết quả
            self.log_message(result_message)
            self.status_var.set("Giải mã hoàn tất")
            self.progress_var.set(100)

        except Exception as e:
            error_message = f"Lỗi khi giải mã file: {str(e)}"
            messagebox.showerror("Lỗi", error_message)
            self.status_var.set("Lỗi khi giải mã")
            self.log_message(f"LỖI: {error_message}")
        finally:
            self.enable_controls()

    def format_hex_data(self, data, bytes_per_line=16):
        """Format dữ liệu hex thành dạng dễ đọc"""
        hex_lines = []
        ascii_lines = []

        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            # Phần hex
            hex_line = ' '.join(f'{b:02x}' for b in chunk)
            hex_lines.append(f'{i:08x}: {hex_line:<48}')

            # Phần ASCII
            ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            ascii_lines.append(f'  |{ascii_line}|')

        # Kết hợp hex và ASCII
        result = []
        for hex_line, ascii_line in zip(hex_lines, ascii_lines):
            result.append(f'{hex_line}{ascii_line}')

        return '\n'.join(result)

    def encrypt_file(self, input_file, output_file, key, iv):
        """Mã hóa file sử dụng AES với mode được chọn."""
        try:
            # Đọc file
            with open(input_file, 'rb') as f:
                data = f.read()

            cipher = AES(key)
            mode = self.mode_var.get()

            # Mã hóa dữ liệu
            if mode == "CBC":
                encrypted_data = cipher.encrypt_cbc(data, iv)

                # Lưu IV vào đầu file mã hóa
                with open(output_file, 'wb') as f:
                    f.write(iv)  # Lưu IV 16 bytes đầu tiên
                    f.write(encrypted_data)  # Tiếp theo là dữ liệu mã hóa
            else:  # ECB mode
                encrypted_data = cipher.encrypt_ecb(data)
                with open(output_file, 'wb') as f:
                    f.write(encrypted_data)

            # Hiển thị kết quả hex
            hex_view = (
                f"DỮ LIỆU MÃ HÓA (HEX VIEW)\n"
                f"{'=' * 50}\n"
                f"Mode: {mode}\n"
                f"File: {output_file}\n"
                f"IV: {iv.hex()}\n"  # Thêm thông tin IV
                f"Độ dài: {len(encrypted_data)} bytes\n"
                f"{'=' * 50}\n\n"
                f"{self.format_hex_data(encrypted_data[:256])}\n\n"
                f"... (còn tiếp)\n"
            )
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(tk.END, hex_view)

            return True

        except Exception as e:
            raise Exception(f"Lỗi khi mã hóa file: {str(e)}")

    def decrypt_file(self, input_file, output_file, key):
        """Giải mã file với mode tương ứng."""
        try:
            # Đọc file mã hóa
            with open(input_file, 'rb') as f:
                if self.mode_var.get() == "CBC":
                    # Đọc IV từ 16 bytes đầu tiên
                    iv = f.read(16)
                    # Đọc phần còn lại là dữ liệu mã hóa
                    encrypted_data = f.read()
                else:
                    encrypted_data = f.read()
                    iv = bytes([0] * 16)  # IV giả cho ECB mode

            cipher = AES(key)

            # Giải mã dữ liệu
            if self.mode_var.get() == "CBC":
                decrypted_data = cipher.decrypt_cbc(encrypted_data, iv)
            else:  # ECB mode
                decrypted_data = cipher.decrypt_ecb(encrypted_data)

            # Lưu file giải mã
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            # Hiển thị kết quả hex
            hex_view = (
                f"DỮ LIỆU GIẢI MÃ (HEX VIEW)\n"
                f"{'=' * 50}\n"
                f"Mode: {self.mode_var.get()}\n"
                f"File: {output_file}\n"
                f"IV: {iv.hex()}\n"  # Thêm thông tin IV
                f"Độ dài: {len(decrypted_data)} bytes\n"
                f"{'=' * 50}\n\n"
                f"{self.format_hex_data(decrypted_data[:256])}\n\n"
                f"... (còn tiếp)\n"
            )
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(tk.END, hex_view)

            return True

        except Exception as e:
            raise Exception(f"Lỗi khi giải mã file: {str(e)}")

    def get_key_iv_from_entries(self):
        try:
            key_text = self.key_entry.get().strip()
            if not key_text:
                raise ValueError("Chưa nhập khóa")

            # Xử lý key dựa trên định dạng được chọn
            key_format = self.key_format.get()
            if key_format == "ascii":
                key = key_text.encode('utf-8')
            elif key_format == "base64":
                try:
                    key = base64.b64decode(key_text)
                except:
                    raise ValueError("Khóa không đúng định dạng Base64")
            else:  # hex
                try:
                    hex_text = key_text.replace(' ', '').replace('0x', '')
                    if len(hex_text) % 2 != 0:
                        raise ValueError("Độ dài chuỗi hex phải là số chẵn")
                    key = bytes.fromhex(hex_text)
                except ValueError as e:
                    if str(e) == "Độ dài chuỗi hex phải là số chẵn":
                        raise
                    raise ValueError("Khóa không đúng định dạng Hex")

            # Kiểm tra IV chỉ khi dùng mode CBC
            if self.mode_var.get() == "CBC":
                iv_text = self.iv_entry.get().strip()
                if not iv_text:
                    raise ValueError("Chưa nhập IV (cần thiết cho CBC mode)")
                try:
                    iv = base64.b64decode(iv_text)
                    if len(iv) != 16:
                        raise ValueError("Độ dài IV phải là 16 bytes")
                except:
                    raise ValueError("IV không đúng định dạng Base64")
            else:
                # Với ECB mode, dùng IV giả
                iv = bytes([0] * 16)

            key_length = int(self.key_length_var.get()) // 8
            if len(key) != key_length:
                if key_format == "ascii":
                    raise ValueError(f"Độ dài khóa ASCII phải là {key_length} ký tự")
                elif key_format == "hex":
                    raise ValueError(f"Độ dài khóa hex phải là {key_length * 2} ký tự")
                else:
                    raise ValueError(f"Độ dài khóa phải là {key_length} bytes")

            return key, iv

        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            return None, None

    def validate_paths(self):
        """Kiểm tra paths hợp lệ"""
        input_path = self.input_file_entry.get().strip()
        output_path = self.output_file_entry.get().strip()

        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Lỗi", "File đầu vào không tồn tại")
            return False

        if not output_path:
            messagebox.showerror("Lỗi", "Chưa chọn file đầu ra")
            return False

        if os.path.exists(output_path):
            if not messagebox.askyesno("Cảnh báo",
                                       "File đầu ra đã tồn tại. Bạn có muốn ghi đè không?"):
                return False

        return True
