import datetime
import tkinter as tk

from aes_gui import AESEncryptionApp

if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptionApp(root)
    root.mainloop()


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


    def toggle_iv_visibility(self):
        """Ẩn/hiện trường IV dựa trên mode được chọn"""
        if self.mode_var.get() == "ECB":
            self.iv_label.grid_remove()
            self.iv_entry.grid_remove()
            self.iv_entry.delete(0, tk.END)  # Xóa giá trị IV
        else:
            self.iv_label.grid()
            self.iv_entry.grid()

