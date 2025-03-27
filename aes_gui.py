import os
import base64
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from datetime import datetime
import time
from aes_core import AES


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
        self.root.geometry("800x600")
        self.root.configure(padx=20, pady=20)

        # Khởi tạo các biến
        self.key = None
        self.iv = None

        # Tạo các frame
        self.create_file_frame()
        self.create_key_frame()
        self.create_mode_frame()
        self.create_control_frame()
        self.create_result_frame()

    def create_file_frame(self):
        """Tạo frame chọn file"""
        file_frame = ttk.LabelFrame(self.root, text="Chọn File")
        file_frame.pack(fill=tk.X, padx=10, pady=10)

        # File đầu vào
        ttk.Label(file_frame, text="File đầu vào:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.input_file_entry = ttk.Entry(file_frame, width=60)
        self.input_file_entry.grid(row=0, column=1, padx=5, pady=5)
        self.browse_input_button = ttk.Button(file_frame, text="Duyệt...",
                                              command=self.browse_input_file)
        self.browse_input_button.grid(row=0, column=2, padx=5, pady=5)

        # File đầu ra
        ttk.Label(file_frame, text="File đầu ra:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.output_file_entry = ttk.Entry(file_frame, width=60)
        self.output_file_entry.grid(row=1, column=1, padx=5, pady=5)
        self.browse_output_button = ttk.Button(file_frame, text="Duyệt...",
                                               command=self.browse_output_file)
        self.browse_output_button.grid(row=1, column=2, padx=5, pady=5)

    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="Chọn File Đầu Vào")
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
        filename = filedialog.asksaveasfilename(title="Chọn File Đầu Ra")
        if filename:
            self.output_file_entry.delete(0, tk.END)
            self.output_file_entry.insert(0, filename)

    def create_key_frame(self):
        """Tạo frame cho phần cài đặt khóa và IV"""
        key_frame = ttk.LabelFrame(self.root, text="Cài đặt Mã hóa")
        key_frame.pack(fill=tk.X, padx=10, pady=10)

        # Nút tạo khóa và IV mới
        ttk.Button(key_frame, text="Tạo Khóa và IV Mới",
                   command=self.generate_key_iv).grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(key_frame, text="- hoặc -").grid(row=0, column=1, padx=5, pady=5)

        # Nhập khóa
        ttk.Label(key_frame, text="Nhập Khóa (Base64):").grid(row=1, column=0,
                                                              sticky=tk.W, padx=5, pady=5)
        self.key_entry = ttk.Entry(key_frame, width=80)
        self.key_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

        # Nhập IV
        ttk.Label(key_frame, text="Nhập IV (Base64):").grid(row=2, column=0,
                                                            sticky=tk.W, padx=5, pady=5)
        self.iv_entry = ttk.Entry(key_frame, width=80)
        self.iv_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)

    def create_mode_frame(self):
        """Tạo frame cho lựa chọn mode và độ dài khóa"""
        # Frame cho độ dài khóa
        key_length_frame = ttk.LabelFrame(self.root, text="Độ dài khóa")
        key_length_frame.pack(fill=tk.X, padx=10, pady=10)

        self.key_length_var = tk.StringVar(value="256")
        ttk.Radiobutton(key_length_frame, text="AES-128 (128 bit)",
                        variable=self.key_length_var, value="128").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(key_length_frame, text="AES-192 (192 bit)",
                        variable=self.key_length_var, value="192").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(key_length_frame, text="AES-256 (256 bit)",
                        variable=self.key_length_var, value="256").pack(side=tk.LEFT, padx=10)

        # Frame cho mode mã hóa
        mode_frame = ttk.LabelFrame(self.root, text="Mode Mã hóa")
        mode_frame.pack(fill=tk.X, padx=10, pady=10)

        self.mode_var = tk.StringVar(value="CBC")
        ttk.Radiobutton(mode_frame, text="ECB Mode (Không khuyến khích)",
                        variable=self.mode_var, value="ECB").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="CBC Mode (Khuyến khích)",
                        variable=self.mode_var, value="CBC").pack(side=tk.LEFT, padx=10)

    def create_control_frame(self):
        """Tạo frame cho các nút điều khiển"""
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        self.encrypt_button = ttk.Button(control_frame, text="Mã hóa File",
                                         command=self.encrypt_file_gui)
        self.encrypt_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.decrypt_button = ttk.Button(control_frame, text="Giải mã File",
                                         command=self.decrypt_file_gui)
        self.decrypt_button.pack(side=tk.LEFT, padx=5, pady=5)

    def create_result_frame(self):
        """Tạo frame cho kết quả và trạng thái"""
        # Frame kết quả
        result_frame = ttk.LabelFrame(self.root, text="Kết quả")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.result_text = tk.Text(result_frame, wrap=tk.WORD, height=15)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Thanh trạng thái
        self.status_var = tk.StringVar()
        self.status_var.set("Sẵn sàng")
        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                               relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=5)

        # Thanh tiến trình
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var,
                                            maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)

    def generate_key_iv(self):
        """Tạo key và IV mới"""
        key_length = int(self.key_length_var.get()) // 8
        self.key = os.urandom(key_length)
        self.iv = os.urandom(16)  # IV luôn là 16 bytes

        # Hiển thị key và IV dưới dạng Base64
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, base64.b64encode(self.key).decode())

        self.iv_entry.delete(0, tk.END)
        self.iv_entry.insert(0, base64.b64encode(self.iv).decode())

        self.log_message(
            f"Đã tạo:\n"
            f"- Khóa AES-{key_length * 8} mới\n"
            f"- IV mới (sẽ tự động tạo IV khác cho mỗi lần mã hóa)"
        )

    def get_key_iv_from_entries(self):
        try:
            key_text = self.key_entry.get().strip()
            iv_text = self.iv_entry.get().strip()

            if not key_text or not iv_text:
                messagebox.showerror("Lỗi", "Khóa và IV không được để trống")
                return None, None

            key = base64.b64decode(key_text)
            iv = base64.b64decode(iv_text)

            key_length = int(self.key_length_var.get()) // 8
            if len(key) != key_length:
                messagebox.showerror("Lỗi",
                                     f"Khóa AES phải có {key_length} bytes ({key_length * 8} bits), hiện tại: {len(key)} bytes")
                return None, None

            if len(iv) != 16:
                messagebox.showerror("Lỗi", f"IV phải có 16 bytes (128 bits), hiện tại: {len(iv)} bytes")
                return None, None

            return key, iv
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi đọc khóa và IV: {str(e)}")
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

    def encrypt_file_gui(self):
        """Xử lý mã hóa file từ GUI"""
        self.disable_controls()
        try:
            if not self.validate_paths():
                return

            input_file = self.input_file_entry.get().strip()
            output_file = self.output_file_entry.get().strip()
            key, iv = self.get_key_iv_from_entries()

            if key is None or iv is None:
                return

            # Cập nhật trạng thái
            self.status_var.set("Đang mã hóa...")
            self.root.update_idletasks()

            # Bắt đầu mã hóa và tính thời gian
            start_time = time.time()
            mode = self.mode_var.get()
            key_length = int(self.key_length_var.get())

            # Thực hiện mã hóa
            self.encrypt_file(input_file, output_file, key, iv)

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
                f"Độ dài khóa: AES-{key_length}\n\n"
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

    def encrypt_file(self, input_file, output_file, key, iv):
        """Mã hóa file sử dụng AES với mode được chọn."""
        try:
            # Đọc file với encoding utf-8
            with open(input_file, 'rb') as f:
                data = f.read()

            cipher = AES(key)
            mode = self.mode_var.get()
            start_time = time.time()

            if mode == "CBC":
                new_iv = os.urandom(16)
                encrypted_data = cipher.encrypt_cbc(data, new_iv)
                with open(output_file, 'wb') as f:
                    # Lưu encoding type (utf-8) vào đầu file
                    f.write(b'CBC_UTF8_' + new_iv + encrypted_data)
            else:  # ECB mode
                encrypted_data = cipher.encrypt_ecb(data)
                dummy_iv = bytes([0] * 16)
                with open(output_file, 'wb') as f:
                    # Lưu encoding type (utf-8) vào đầu file
                    f.write(b'ECB_UTF8_' + dummy_iv + encrypted_data)

            encryption_time = time.time() - start_time
            if encryption_time == 0:
                encryption_time = 0.0001

            input_size = os.path.getsize(input_file)
            output_size = os.path.getsize(output_file)
            throughput = input_size / encryption_time / 1024 / 1024

            self.log_message(f"Mã hóa thành công!\n"
                             f"Mode: {mode}\n"
                             f"File gốc: {input_file}\n"
                             f"File mã hóa: {output_file}\n"
                             f"Kích thước file gốc: {input_size:,} bytes\n"
                             f"Kích thước file mã hóa: {output_size:,} bytes\n"
                             f"Thời gian mã hóa: {encryption_time:.6f} giây\n"
                             f"Tốc độ mã hóa: {throughput:.2f} MB/giây")

        except Exception as e:
            raise Exception(f"Lỗi khi mã hóa file: {str(e)}")

    def decrypt_file(self, input_file, output_file, key):
        """Giải mã file với mode tương ứng."""
        try:
            with open(input_file, 'rb') as f:
                data = f.read()

            if len(data) < 25:  # 9 bytes cho header + 16 bytes cho IV
                raise ValueError("File mã hóa không hợp lệ")

            # Đọc header từ file
            if data.startswith(b'CBC_UTF8_'):
                mode = "CBC"
                iv_start = 9
            elif data.startswith(b'ECB_UTF8_'):
                mode = "ECB"
                iv_start = 9
            else:
                raise ValueError("File mã hóa không hợp lệ hoặc bị hỏng")

            iv = data[iv_start:iv_start + 16]
            encrypted_data = data[iv_start + 16:]

            cipher = AES(key)
            start_time = time.time()

            # Giải mã dữ liệu
            if mode == "CBC":
                decrypted_data = cipher.decrypt_cbc(encrypted_data, iv)
            else:  # ECB mode
                decrypted_data = cipher.decrypt_ecb(encrypted_data)

            # Ghi file với encoding utf-8
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            decryption_time = time.time() - start_time
            if decryption_time == 0:
                decryption_time = 0.0001

            input_size = os.path.getsize(input_file)
            output_size = os.path.getsize(output_file)
            throughput = output_size / decryption_time / 1024 / 1024

            # Kiểm tra nội dung giải mã
            try:
                with open(output_file, 'rb') as f:
                    content = f.read()
                content.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Giải mã không thành công: Dữ liệu không phải UTF-8 hợp lệ")

            # Sử dụng format hiển thị kết quả như cũ
            self.log_message(f"Giải mã thành công!\n"
                             f"File mã hóa: {input_file}\n"
                             f"File giải mã: {output_file}\n"
                             f"Kích thước file mã hóa: {input_size:,} bytes\n"
                             f"Kích thước file giải mã: {output_size:,} bytes\n"
                             f"Thời gian giải mã: {decryption_time:.6f} giây\n"
                             f"Tốc độ giải mã: {throughput:.2f} MB/giây")

        except Exception as e:
            raise Exception(f"Lỗi khi giải mã file: {str(e)}")

    def log_message(self, message):
        """Ghi log và hiển thị kết quả"""
        # Lấy thời gian hiện tại
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Format log entry
        log_entry = f"[{current_time}]\n{message}\n"
        log_entry += "=" * 50 + "\n"  # Thêm dòng phân cách

        # Ghi vào file log
        try:
            with open("D:/KMA/AES/log.txt", "a", encoding="utf-8") as log_file:
                log_file.write(log_entry)
        except Exception as e:
            print(f"Lỗi khi ghi log: {str(e)}")

        # Hiển thị trên GUI
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, message)
