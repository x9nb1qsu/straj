import sys
import os
import json
import hashlib
import shutil
import re
from uuid import uuid4
from datetime import datetime, timedelta, date

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QComboBox, QFileDialog, QMessageBox, QDialog,
    QGridLayout, QDateEdit, QTextEdit, QScrollArea, QFrame, QMainWindow,
    QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy, QGroupBox,
    QDialogButtonBox
)
from PyQt5.QtGui import QPixmap, QImageReader, QIntValidator, QFont, QIcon, QRegExpValidator, QColor
from PyQt5.QtCore import Qt, QSize, QDate, QRegExp, QTimer

# --- Configuration and Constants ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
PHOTOS_DIR = os.path.join(DATA_DIR, "photos")
SCANS_DIR = os.path.join(DATA_DIR, "scans")
GROUP_LISTS_DIR = os.path.join(DATA_DIR, "group_lists")  # For templates and uploaded lists

USERS_FILE = os.path.join(DATA_DIR, "users.json")
EMPLOYEES_FILE = os.path.join(DATA_DIR, "employees.json")
PASS_REQUESTS_FILE = os.path.join(DATA_DIR, "pass_requests.json")
VISIT_LOG_FILE = os.path.join(DATA_DIR, "visit_log.json")  # For emulator

PHOTO_MAX_SIZE_MB = 2
PHOTO_ASPECT_RATIO_W = 3
PHOTO_ASPECT_RATIO_H = 4
PHOTO_PREVIEW_SIZE = QSize(100, 133)

VISITOR_PHOTO_MAX_SIZE_MB = 4  # As per TZ for visitor photo
SCAN_MAX_SIZE_MB = 4  # Assuming same as visitor photo for scans


# --- Utility Functions ---

def ensure_data_dirs_files():
    """Creates necessary data directories and initial JSON files if they don't exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(PHOTOS_DIR, exist_ok=True)
    os.makedirs(SCANS_DIR, exist_ok=True)
    os.makedirs(GROUP_LISTS_DIR, exist_ok=True)

    if not os.path.exists(USERS_FILE):
        default_users = {
            "guardianskk": {
                "password_hash": hash_password("AdminPass123!"),
                "secret_word_hash": hash_password("AdminSecret"),
                "full_name": "Администратов Админ Админович",
                "role": "admin"
            },
            "defendservice": {
                "password_hash": hash_password("SecurityPass123!"),
                "secret_word_hash": hash_password("SecuritySecret"),
                "full_name": "Безопасников Охран Охранович",
                "role": "security"
            }
        }
        save_json(USERS_FILE, default_users)

    for filepath in [EMPLOYEES_FILE, PASS_REQUESTS_FILE, VISIT_LOG_FILE]:
        if not os.path.exists(filepath):
            save_json(filepath, [])


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(stored_hash, provided_password):
    return stored_hash == hash_password(provided_password)


def load_json(filepath, default_type=list):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {} if default_type == dict else []
    except json.JSONDecodeError:
        QMessageBox.warning(None, "Ошибка данных", f"Файл {os.path.basename(filepath)} поврежден или пуст.")
        return {} if default_type == dict else []


def save_json(filepath, data):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    except IOError:
        QMessageBox.critical(None, "Ошибка записи", f"Не удалось сохранить данные в файл {os.path.basename(filepath)}.")


def validate_password_complexity(password):
    if len(password) < 8: return False, "Пароль должен быть не менее 8 символов."
    if not re.search(r"[A-Z]", password): return False, "Пароль должен содержать хотя бы одну заглавную букву."
    if not re.search(r"[a-z]", password): return False, "Пароль должен содержать хотя бы одну строчную букву."
    if not re.search(r"\d", password): return False, "Пароль должен содержать хотя бы одну цифру."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]",
                     password): return False, "Пароль должен содержать хотя бы один специальный символ."
    return True, ""


def validate_photo_or_scan(filepath, max_size_mb, aspect_w=None, aspect_h=None, is_scan=False):
    if not filepath: return False, "Файл не выбран."
    ext = os.path.splitext(filepath)[1].lower()
    allowed_exts = ['.jpg', '.jpeg'] if is_scan else ['.jpg', '.jpeg', '.png']
    if ext not in allowed_exts:
        return False, f"Неверный формат файла. Допустимы: {', '.join(allowed_exts).upper()}."

    # Check if the file actually exists before getting its size
    if not os.path.exists(filepath):
        return False, f"Файл по пути '{filepath}' не найден."

    file_size_bytes = os.path.getsize(filepath)
    if file_size_bytes > max_size_mb * 1024 * 1024:
        return False, f"Размер файла не должен превышать {max_size_mb} МБ."

    if aspect_w and aspect_h:  # Only validate aspect ratio if provided (for photos)
        try:
            reader = QImageReader(filepath)
            if not reader.canRead(): return False, "Не удалось прочитать изображение."
            img_size = reader.size()
            width, height = img_size.width(), img_size.height()
            if width <= 0 or height <= 0: return False, "Некорректные размеры изображения."

            if aspect_w < aspect_h and width > height: return False, "Изображение должно быть вертикальным."
            if aspect_w > aspect_h and height > width: return False, "Изображение должно быть горизонтальным."

            target_ratio = aspect_w / aspect_h
            actual_ratio = width / height
            if not (target_ratio * 0.98 <= actual_ratio <= target_ratio * 1.02):
                return False, f"Соотношение сторон изображения должно быть {aspect_w}x{aspect_h}."
        except Exception as e:
            return False, f"Ошибка при проверке изображения: {str(e)}"
    return True, ""


def show_message(parent, title, message, icon=QMessageBox.Information):
    msg_box = QMessageBox(parent)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setIcon(icon)
    msg_box.setStandardButtons(QMessageBox.Ok)
    msg_box.exec_()


def get_fio_short(full_name_str):
    parts = full_name_str.split()
    if len(parts) >= 1:
        fio_display = parts[0]  # Фамилия
        if len(parts) >= 2: fio_display += f" {parts[1][0]}."  # И.
        if len(parts) >= 3: fio_display += f"{parts[2][0]}."  # О.
        return fio_display
    return full_name_str


# --- Base Window Class ---
class BaseWindow(QMainWindow):
    def __init__(self, current_user_info=None, parent=None):
        super().__init__(parent)
        self.current_user_info = current_user_info
        self.user_name_label = QLabel("")
        if self.current_user_info and "full_name" in self.current_user_info:
            self.user_name_label.setText(get_fio_short(self.current_user_info["full_name"]))
        self.user_name_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.user_name_label.setStyleSheet("padding-right: 10px; font-weight: bold;")

    def _create_status_bar_with_user(self):
        status_bar = self.statusBar()
        status_bar.addPermanentWidget(self.user_name_label, 1)
        status_bar.setStyleSheet("QStatusBar { border-top: 1px solid #ccc; }")
        return status_bar

    def _add_user_display_to_layout(self, layout, is_dialog=False):
        user_display_layout = QHBoxLayout()
        user_display_layout.addStretch()
        user_display_layout.addWidget(self.user_name_label)
        if is_dialog:  # For QDialog, directly add to its main layout
            layout.insertLayout(0, user_display_layout)
            separator = QFrame()
            separator.setFrameShape(QFrame.HLine)
            separator.setFrameShadow(QFrame.Sunken)
            layout.insertWidget(1, separator)
            layout.insertSpacing(2, 10)


# --- Login Window ---
class LoginWindow(QWidget):
    def __init__(self, main_app_controller):
        super().__init__()
        self.main_app_controller = main_app_controller
        self.setWindowTitle("Стражник - Вход")
        self.setMinimumWidth(350)
        self.setWindowIcon(QIcon())  # Placeholder for app icon
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        title_label = QLabel("Вход в систему «Стражник»")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        self.user_type_combo = QComboBox()
        self.user_type_combo.addItems(
            ["Выберите тип пользователя", "Администратор доступа", "Сотрудник службы безопасности"])
        layout.addWidget(QLabel("Тип пользователя:"))
        layout.addWidget(self.user_type_combo)

        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("Введите логин")
        layout.addWidget(QLabel("Логин:"))
        layout.addWidget(self.login_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Введите пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password_input)

        self.secret_word_input = QLineEdit()
        self.secret_word_input.setPlaceholderText("Введите секретное слово")
        self.secret_word_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Секретное слово:"))
        layout.addWidget(self.secret_word_input)

        self.login_button = QPushButton("Войти в систему")
        self.login_button.setStyleSheet("padding: 10px; font-size: 14px;")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)

        forgot_label = QLabel("<a href='#'>Забыли данные для входа?</a>")
        forgot_label.setAlignment(Qt.AlignCenter)
        forgot_label.linkActivated.connect(self.handle_forgot_details)
        layout.addWidget(forgot_label)
        self.setLayout(layout)

    def handle_login(self):
        user_type_text = self.user_type_combo.currentText()
        login = self.login_input.text().strip()
        password = self.password_input.text()
        secret_word = self.secret_word_input.text()

        if user_type_text == "Выберите тип пользователя":
            show_message(self, "Ошибка входа", "Пожалуйста, выберите тип пользователя.")
            return
        if not login or not password or not secret_word:
            show_message(self, "Ошибка входа", "Все поля должны быть заполнены.")
            return

        users_data = load_json(USERS_FILE, default_type=dict)
        user_info = users_data.get(login)
        expected_role = "admin" if user_type_text == "Администратор доступа" else "security"

        if user_info and user_info.get("role") == expected_role:
            if verify_password(user_info.get("password_hash", ""), password):
                if verify_password(user_info.get("secret_word_hash", ""), secret_word):
                    is_complex, msg = validate_password_complexity(password)
                    if not is_complex:
                        show_message(self, "Ошибка входа", f"Пароль не соответствует требованиям сложности: {msg}",
                                     QMessageBox.Warning)
                        return

                    show_message(self, "Успешный вход", f"Добро пожаловать, {get_fio_short(user_info['full_name'])}!")
                    self.main_app_controller.show_main_window(user_info)
                    self.close()
                else:
                    show_message(self, "Ошибка входа", "Неверное секретное слово.", QMessageBox.Warning)
            else:
                show_message(self, "Ошибка входа", "Неверный пароль.", QMessageBox.Warning)
        else:
            show_message(self, "Ошибка входа", "Пользователь не найден или неверный тип пользователя.",
                         QMessageBox.Warning)

    def handle_forgot_details(self):
        show_message(self, "Восстановление доступа",
                     "Функция восстановления доступа еще не реализована. Обратитесь к системному администратору.")


# --- Admin Main Dashboard ---
class AdminDashboardWindow(BaseWindow):
    def __init__(self, current_user_info, main_app_controller):
        super().__init__(current_user_info)
        self.main_app_controller = main_app_controller
        self.setWindowTitle("Стражник - Панель Администратора")
        self.setMinimumSize(600, 400)
        self.init_ui()
        self._create_status_bar_with_user()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        title_label = QLabel("Панель Администратора Доступа")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        layout.addSpacing(20)

        manage_employees_button = QPushButton("Управление данными сотрудников")
        manage_employees_button.clicked.connect(self.open_employee_management)
        layout.addWidget(manage_employees_button)

        review_requests_button = QPushButton("Просмотр и обработка заявок на пропуск")
        review_requests_button.clicked.connect(self.open_request_review)
        layout.addWidget(review_requests_button)

        layout.addStretch()
        logout_button = QPushButton("Выход из системы")
        logout_button.clicked.connect(self.handle_logout)
        layout.addWidget(logout_button, alignment=Qt.AlignRight)

    def open_employee_management(self):
        self.emp_management_window = AdminAccessManagementWindow(self.current_user_info, self.main_app_controller,
                                                                 parent_dashboard=self)
        self.emp_management_window.show()
        self.hide()

    def open_request_review(self):
        self.req_review_window = AdminRequestReviewWindow(self.current_user_info, self.main_app_controller,
                                                          parent_dashboard=self)
        self.req_review_window.show()
        self.hide()

    def handle_logout(self):
        self.main_app_controller.show_login_window()
        self.close()


# --- Admin Access Management Window (Employee Data) ---
class AdminAccessManagementWindow(BaseWindow):
    def __init__(self, current_user_info, main_app_controller, parent_dashboard=None):
        super().__init__(current_user_info)
        self.main_app_controller = main_app_controller
        self.parent_dashboard = parent_dashboard
        self.setWindowTitle("Стражник - Управление данными сотрудников")
        self.setMinimumSize(600, 450)
        self.selected_photo_path = None
        self.init_ui()
        self._create_status_bar_with_user()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 10, 20, 20)

        form_layout = QGridLayout()
        form_layout.setHorizontalSpacing(15)
        form_layout.setVerticalSpacing(10)

        form_fields_widget = QWidget()
        fields_layout = QVBoxLayout(form_fields_widget)
        fields_layout.addWidget(QLabel("Фамилия:"))
        self.last_name_input = QLineEdit()
        fields_layout.addWidget(self.last_name_input)
        fields_layout.addWidget(QLabel("Имя:"))
        self.first_name_input = QLineEdit()
        fields_layout.addWidget(self.first_name_input)
        fields_layout.addWidget(QLabel("Отчество:"))
        self.patronymic_input = QLineEdit()
        fields_layout.addWidget(self.patronymic_input)
        fields_layout.addWidget(QLabel("Пол:"))
        self.gender_combo = QComboBox()
        self.gender_combo.addItems(["Выберите пол", "Мужской", "Женский"])
        fields_layout.addWidget(self.gender_combo)
        fields_layout.addWidget(QLabel("Должность:"))
        self.position_input = QLineEdit()
        fields_layout.addWidget(self.position_input)
        fields_layout.addWidget(QLabel("Подразделение:"))
        self.department_input = QLineEdit()
        fields_layout.addWidget(self.department_input)
        fields_layout.addStretch()

        photo_section_widget = QWidget()
        photo_layout = QVBoxLayout(photo_section_widget)
        photo_layout.setAlignment(Qt.AlignTop)
        self.photo_label = QLabel("Фотография\n(3x4, верт.)")
        self.photo_label.setFixedSize(PHOTO_PREVIEW_SIZE)
        self.photo_label.setAlignment(Qt.AlignCenter)
        self.photo_label.setStyleSheet("border: 1px solid #ccc; background-color: #f0f0f0;")
        photo_layout.addWidget(self.photo_label)
        self.upload_photo_button = QPushButton("Загрузить фото")
        self.upload_photo_button.clicked.connect(self.handle_upload_photo)
        photo_layout.addWidget(self.upload_photo_button)
        photo_layout.addStretch()

        form_layout.addWidget(form_fields_widget, 0, 0)
        form_layout.addWidget(photo_section_widget, 0, 1, Qt.AlignTop)
        form_layout.setColumnStretch(0, 2)
        form_layout.setColumnStretch(1, 1)
        main_layout.addLayout(form_layout)
        main_layout.addStretch(1)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.save_button = QPushButton("Сохранить")
        self.save_button.clicked.connect(self.handle_save)
        button_layout.addWidget(self.save_button)
        self.cancel_button = QPushButton("Отменить")
        self.cancel_button.clicked.connect(self.handle_cancel)
        button_layout.addWidget(self.cancel_button)
        main_layout.addLayout(button_layout)

    def handle_upload_photo(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Выбрать фото", "", "Images (*.png *.jpg *.jpeg)")
        if filepath:
            is_valid, msg = validate_photo_or_scan(filepath, PHOTO_MAX_SIZE_MB, PHOTO_ASPECT_RATIO_W,
                                                   PHOTO_ASPECT_RATIO_H)
            if is_valid:
                self.selected_photo_path = filepath
                pixmap = QPixmap(filepath)
                self.photo_label.setPixmap(
                    pixmap.scaled(PHOTO_PREVIEW_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                show_message(self, "Ошибка фото", msg, QMessageBox.Warning)
                self.selected_photo_path = None
                self.photo_label.setText("Фото не\nсоответствует")
                self.photo_label.setPixmap(QPixmap())

    def clear_form(self):
        self.last_name_input.clear()
        self.first_name_input.clear()
        self.patronymic_input.clear()
        self.gender_combo.setCurrentIndex(0)
        self.position_input.clear()
        self.department_input.clear()
        self.photo_label.setText("Фотография\n(3x4, верт.)")
        self.photo_label.setPixmap(QPixmap())
        self.selected_photo_path = None

    def handle_save(self):
        last_name = self.last_name_input.text().strip()
        first_name = self.first_name_input.text().strip()
        patronymic = self.patronymic_input.text().strip()
        gender = self.gender_combo.currentText()
        position = self.position_input.text().strip()
        department = self.department_input.text().strip()

        if not all([last_name, first_name, position, department]):
            show_message(self, "Ошибка", "Фамилия, Имя, Должность и Подразделение обязательны.", QMessageBox.Warning)
            return
        if gender == "Выберите пол":
            show_message(self, "Ошибка", "Выберите пол.", QMessageBox.Warning)
            return
        if not self.selected_photo_path:
            show_message(self, "Ошибка", "Загрузите фотографию.", QMessageBox.Warning)
            return

        _, ext = os.path.splitext(self.selected_photo_path)
        new_photo_filename = f"emp_{uuid4()}{ext}"
        destination_photo_path = os.path.join(PHOTOS_DIR, new_photo_filename)
        try:
            shutil.copy(self.selected_photo_path, destination_photo_path)
        except Exception as e:
            show_message(self, "Ошибка", f"Не удалось сохранить фото: {e}", QMessageBox.Critical)
            return

        employee_data = {
            "id": str(uuid4()), "last_name": last_name, "first_name": first_name,
            "patronymic": patronymic, "gender": gender, "position": position,
            "department": department, "photo_path": os.path.join("photos", new_photo_filename)
        }
        employees = load_json(EMPLOYEES_FILE)
        employees.append(employee_data)
        save_json(EMPLOYEES_FILE, employees)
        show_message(self, "Успех", "Данные сотрудника сохранены.")
        self.clear_form()
        self.close()

    def handle_cancel(self):
        if self.last_name_input.text() or self.first_name_input.text() or self.selected_photo_path:
            reply = QMessageBox.question(self, "Отмена", "Отменить ввод? Несохраненные данные будут потеряны.",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.clear_form()
                self.close()
        else:
            self.close()

    def closeEvent(self, event):
        if self.parent_dashboard:
            self.parent_dashboard.show()
        super().closeEvent(event)


# --- Edit Request Dialog ---
class EditRequestDialog(QDialog):
    def __init__(self, request_data, current_user_info, parent=None):
        super().__init__(parent)
        self.request_data_orig = request_data  # Keep original for comparison or if needed
        self.request_data_edited = dict(request_data)  # Work on a copy
        self.current_user_info = current_user_info  # For consistency, though admin is editing
        self.parent_window = parent  # To call refresh on parent

        self.setWindowTitle(f"Редактирование заявки ID: {self.request_data_orig.get('request_id')}")
        self.setMinimumSize(700, 700)  # Similar to creation forms
        self.setModal(True)

        self.selected_visitor_photo_path = self.request_data_orig.get(
            "visitor_photo_path")  # Store original path or new path
        self.selected_passport_scan_path = self.request_data_orig.get("passport_scan_path")

        # These will store the path to a NEWLY uploaded file during this edit session
        self._newly_uploaded_visitor_photo = None
        self._newly_uploaded_passport_scan = None

        self.init_ui()
        self.populate_form()

    def _create_styled_groupbox(self, title):  # Copied helper
        group_box = QGroupBox(title)
        group_box.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 1px solid #4682B4; border-radius: 5px; margin-top: 1ex; background-color: #E6F2FF; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; background-color: #4682B4; color: white; border-radius: 3px;}
        """)  # Using a blueish theme for edit dialog
        return group_box

    def init_ui(self):
        main_layout_dialog = QVBoxLayout(self)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_area.setWidget(scroll_content)

        layout = QVBoxLayout(scroll_content)  # Main layout for content inside scroll area
        main_layout_dialog.addWidget(scroll_area)

        # --- Form fields based on request type ---
        if self.request_data_orig.get("request_type") == "individual":
            # --- Section 1: Информация для пропуска & Принимающая сторона ---
            top_grid = QGridLayout()
            pass_info_group = self._create_styled_groupbox("Информация для пропуска")
            pass_info_layout = QGridLayout(pass_info_group)
            pass_info_layout.addWidget(QLabel("Срок действия заявки: c*"), 0, 0)
            self.visit_date_from_edit = QDateEdit(calendarPopup=True)
            self.visit_date_from_edit.setMinimumDate(
                QDate.currentDate().addDays(1))  # Or allow past if editing approved? For now, same as creation.
            self.visit_date_from_edit.setMaximumDate(QDate.currentDate().addDays(150))  # Extended range for editing
            self.visit_date_from_edit.dateChanged.connect(self._update_date_to_min_edit)
            pass_info_layout.addWidget(self.visit_date_from_edit, 0, 1)
            pass_info_layout.addWidget(QLabel("по*"), 0, 2)
            self.visit_date_to_edit = QDateEdit(calendarPopup=True)
            pass_info_layout.addWidget(self.visit_date_to_edit, 0, 3)
            pass_info_layout.addWidget(QLabel("Цель посещения*:"), 1, 0)
            self.visit_purpose_edit = QLineEdit()
            pass_info_layout.addWidget(self.visit_purpose_edit, 1, 1, 1, 3)
            top_grid.addWidget(pass_info_group, 0, 0)

            receiving_party_group = self._create_styled_groupbox("Принимающая сторона")
            receiving_party_layout = QGridLayout(receiving_party_group)
            receiving_party_layout.addWidget(QLabel("Подразделение*:"), 0, 0)
            self.department_combo = QComboBox()
            self.load_departments()
            self.department_combo.currentIndexChanged.connect(self.load_employees_for_department)
            receiving_party_layout.addWidget(self.department_combo, 0, 1)
            receiving_party_layout.addWidget(QLabel("ФИО сотрудника*:"), 1, 0)
            self.employee_fio_combo = QComboBox()
            receiving_party_layout.addWidget(self.employee_fio_combo, 1, 1)
            top_grid.addWidget(receiving_party_group, 0, 1)
            layout.addLayout(top_grid)

            # --- Section 2: Информация о посетителе ---
            visitor_info_group = self._create_styled_groupbox("Информация о посетителе")
            visitor_info_layout = QGridLayout(visitor_info_group)
            visitor_info_layout.addWidget(QLabel("Фамилия*:"), 0, 0)
            self.visitor_last_name_edit = QLineEdit()
            visitor_info_layout.addWidget(self.visitor_last_name_edit, 0, 1)
            visitor_info_layout.addWidget(QLabel("Организация:"), 0, 2)
            self.visitor_organization_edit = QLineEdit()
            visitor_info_layout.addWidget(self.visitor_organization_edit, 0, 3)
            visitor_info_layout.addWidget(QLabel("Имя*:"), 1, 0)
            self.visitor_first_name_edit = QLineEdit()
            visitor_info_layout.addWidget(self.visitor_first_name_edit, 1, 1)
            visitor_info_layout.addWidget(QLabel("Примечание*:"), 1, 2)
            self.visitor_note_edit = QLineEdit()
            visitor_info_layout.addWidget(self.visitor_note_edit, 1, 3)
            visitor_info_layout.addWidget(QLabel("Отчество:"), 2, 0)
            self.visitor_patronymic_edit = QLineEdit()
            visitor_info_layout.addWidget(self.visitor_patronymic_edit, 2, 1)
            visitor_info_layout.addWidget(QLabel("Дата рождения*:"), 2, 2)
            self.visitor_dob_edit = QDateEdit(calendarPopup=True)
            self.visitor_dob_edit.setMaximumDate(QDate.currentDate().addYears(-14))
            visitor_info_layout.addWidget(self.visitor_dob_edit, 2, 3)
            visitor_info_layout.addWidget(QLabel("Телефон:"), 3, 0)
            self.visitor_phone_edit = QLineEdit()
            self.visitor_phone_edit.setInputMask("+7 (999) 999-99-99;_")
            visitor_info_layout.addWidget(self.visitor_phone_edit, 3, 1)
            visitor_info_layout.addWidget(QLabel("Серия паспорта*:"), 3, 2)
            self.visitor_passport_series_edit = QLineEdit()
            self.visitor_passport_series_edit.setMaxLength(4)
            self.visitor_passport_series_edit.setValidator(QRegExpValidator(QRegExp("\\d{4}")))
            visitor_info_layout.addWidget(self.visitor_passport_series_edit, 3, 3)
            visitor_info_layout.addWidget(QLabel("E-mail*:"), 4, 0)
            self.visitor_email_edit = QLineEdit()
            self.visitor_email_edit.setValidator(QRegExpValidator(QRegExp("[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,4}")))
            visitor_info_layout.addWidget(self.visitor_email_edit, 4, 1)
            visitor_info_layout.addWidget(QLabel("Номер паспорта*:"), 4, 2)
            self.visitor_passport_number_edit = QLineEdit()
            self.visitor_passport_number_edit.setMaxLength(6)
            self.visitor_passport_number_edit.setValidator(QRegExpValidator(QRegExp("\\d{6}")))
            visitor_info_layout.addWidget(self.visitor_passport_number_edit, 4, 3)

            self.visitor_photo_label = QLabel("Фото посетителя")
            self.visitor_photo_label.setFixedSize(PHOTO_PREVIEW_SIZE)
            self.visitor_photo_label.setAlignment(Qt.AlignCenter)
            self.visitor_photo_label.setStyleSheet("border: 1px solid #ccc; background-color: #f0f0f0;")
            visitor_info_layout.addWidget(self.visitor_photo_label, 0, 4, 3, 1, Qt.AlignTop | Qt.AlignCenter)
            self.upload_visitor_photo_button = QPushButton("Изменить фото")
            self.upload_visitor_photo_button.clicked.connect(self.handle_upload_visitor_photo_edit)
            visitor_info_layout.addWidget(self.upload_visitor_photo_button, 3, 4, Qt.AlignTop | Qt.AlignCenter)
            layout.addWidget(visitor_info_group)

            # --- Section 3: Прикрепляемые документы ---
            docs_group = self._create_styled_groupbox("Прикрепляемые документы")
            docs_layout = QHBoxLayout(docs_group)
            self.upload_scan_button = QPushButton("Изменить скан паспорта (JPG)*")
            self.upload_scan_button.clicked.connect(self.handle_upload_scan_edit)
            self.scan_filename_label = QLabel("Файл не выбран")
            docs_layout.addWidget(self.upload_scan_button)
            docs_layout.addWidget(self.scan_filename_label)
            docs_layout.addStretch()
            layout.addWidget(docs_group)

        elif self.request_data_orig.get("request_type") == "group":
            # Simplified editing for group for now
            group_main_info_box = self._create_styled_groupbox("Общая информация по групповой заявке")
            group_main_layout = QGridLayout(group_main_info_box)

            group_main_layout.addWidget(QLabel("Срок действия заявки: c*"), 0, 0)
            self.visit_date_from_edit = QDateEdit(calendarPopup=True)  # Common field
            group_main_layout.addWidget(self.visit_date_from_edit, 0, 1)
            group_main_layout.addWidget(QLabel("по*"), 0, 2)
            self.visit_date_to_edit = QDateEdit(calendarPopup=True)  # Common field
            group_main_layout.addWidget(self.visit_date_to_edit, 0, 3)

            group_main_layout.addWidget(QLabel("Цель посещения*:"), 1, 0)
            self.visit_purpose_edit = QLineEdit()  # Common field
            group_main_layout.addWidget(self.visit_purpose_edit, 1, 1, 1, 3)

            group_main_layout.addWidget(QLabel("Подразделение*:"), 2, 0)
            self.department_combo = QComboBox()  # Common field
            self.load_departments()
            self.department_combo.currentIndexChanged.connect(self.load_employees_for_department)
            group_main_layout.addWidget(self.department_combo, 2, 1)

            group_main_layout.addWidget(QLabel("ФИО сотрудника*:"), 3, 0)
            self.employee_fio_combo = QComboBox()  # Common field
            group_main_layout.addWidget(self.employee_fio_combo, 3, 1)

            layout.addWidget(group_main_info_box)

            contact_person_box = self._create_styled_groupbox("Контактное лицо группы (заявитель)")
            contact_layout = QGridLayout(contact_person_box)
            contact_layout.addWidget(QLabel("Фамилия*:"), 0, 0)
            self.contact_last_name_edit = QLineEdit()
            contact_layout.addWidget(self.contact_last_name_edit, 0, 1)
            contact_layout.addWidget(QLabel("Имя*:"), 0, 2)
            self.contact_first_name_edit = QLineEdit()
            contact_layout.addWidget(self.contact_first_name_edit, 0, 3)
            # Add other contact fields if needed for editing (phone, email, org, note)
            layout.addWidget(contact_person_box)

            visitors_list_box = self._create_styled_groupbox("Список посетителей (просмотр)")
            visitors_list_layout_view = QVBoxLayout(visitors_list_box)
            self.group_visitors_table_view = QTableWidget()  # For display only for now
            self.group_visitors_table_view.setEditTriggers(QTableWidget.NoEditTriggers)
            visitors_list_layout_view.addWidget(self.group_visitors_table_view)
            layout.addWidget(visitors_list_box)
            # TODO: Populate self.group_visitors_table_view

        else:
            layout.addWidget(QLabel("Тип заявки не поддерживается для редактирования в этой версии."))

        layout.addStretch()

        # --- Buttons ---
        self.button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.handle_save_changes)
        self.button_box.rejected.connect(self.reject)
        main_layout_dialog.addWidget(self.button_box)

    def _update_date_to_min_edit(self):  # Copied from creation form
        min_date_to = self.visit_date_from_edit.date()
        # Allow wider range for editing if needed, or keep strict
        max_date_to = self.visit_date_from_edit.date().addDays(150)  # Extended range

        self.visit_date_to_edit.setMinimumDate(min_date_to)
        self.visit_date_to_edit.setMaximumDate(max_date_to)
        if self.visit_date_to_edit.date() < min_date_to:
            self.visit_date_to_edit.setDate(min_date_to)

    def load_departments(self):  # Copied
        employees_data = load_json(EMPLOYEES_FILE)
        departments = sorted(list(set(emp.get("department", "Не указано") for emp in employees_data)))
        self.department_combo.clear()
        self.department_combo.addItem("Выберите подразделение")
        self.department_combo.addItems(departments)

    def load_employees_for_department(self):  # Copied
        selected_department = self.department_combo.currentText()
        self.employee_fio_combo.clear()
        self.employee_fio_combo.addItem("Выберите сотрудника")
        if selected_department != "Выберите подразделение" and selected_department != "":
            employees_data = load_json(EMPLOYEES_FILE)
            department_employees = [
                f"{emp['last_name']} {emp['first_name']} {emp.get('patronymic', '')}".strip()
                for emp in employees_data if emp.get("department") == selected_department
            ]
            self.employee_fio_combo.addItems(sorted(department_employees))

    def populate_form(self):
        req = self.request_data_orig
        if req.get("request_type") == "individual":
            self.visit_date_from_edit.setDate(QDate.fromString(req.get("visit_date_from", ""), Qt.ISODate))
            self.visit_date_to_edit.setDate(QDate.fromString(req.get("visit_date_to", ""), Qt.ISODate))
            self._update_date_to_min_edit()  # Ensure 'to_date' is valid after 'from_date' is set
            self.visit_purpose_edit.setText(req.get("visit_purpose", ""))

            dep_idx = self.department_combo.findText(req.get("target_department", ""))
            self.department_combo.setCurrentIndex(dep_idx if dep_idx != -1 else 0)
            # Need to manually trigger employee loading if department was found and set
            if dep_idx != -1: self.load_employees_for_department()
            emp_idx = self.employee_fio_combo.findText(req.get("target_employee_fio", ""))
            self.employee_fio_combo.setCurrentIndex(emp_idx if emp_idx != -1 else 0)

            self.visitor_last_name_edit.setText(req.get("visitor_last_name", ""))
            self.visitor_first_name_edit.setText(req.get("visitor_first_name", ""))
            self.visitor_patronymic_edit.setText(req.get("visitor_patronymic", ""))
            self.visitor_organization_edit.setText(req.get("visitor_organization", ""))
            self.visitor_note_edit.setText(req.get("visitor_note", ""))
            self.visitor_dob_edit.setDate(QDate.fromString(req.get("visitor_dob", ""), Qt.ISODate))
            self.visitor_phone_edit.setText(req.get("visitor_phone", ""))
            self.visitor_email_edit.setText(req.get("visitor_email", ""))
            self.visitor_passport_series_edit.setText(req.get("visitor_passport_series", ""))
            self.visitor_passport_number_edit.setText(req.get("visitor_passport_number", ""))

            if self.selected_visitor_photo_path:
                full_photo_path = os.path.join(DATA_DIR, self.selected_visitor_photo_path)
                if os.path.exists(full_photo_path):
                    pixmap = QPixmap(full_photo_path)
                    self.visitor_photo_label.setPixmap(
                        pixmap.scaled(PHOTO_PREVIEW_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                else:
                    self.visitor_photo_label.setText("Фото не найдено")
            else:
                self.visitor_photo_label.setText("Фото не было\nзагружено")

            if self.selected_passport_scan_path:
                self.scan_filename_label.setText(os.path.basename(self.selected_passport_scan_path))
            else:
                self.scan_filename_label.setText("Скан не был загружен")

        elif req.get("request_type") == "group":
            self.visit_date_from_edit.setDate(QDate.fromString(req.get("visit_date_from", ""), Qt.ISODate))
            self.visit_date_to_edit.setDate(QDate.fromString(req.get("visit_date_to", ""), Qt.ISODate))
            self.visit_purpose_edit.setText(req.get("visit_purpose", ""))
            dep_idx = self.department_combo.findText(req.get("target_department", ""))
            self.department_combo.setCurrentIndex(dep_idx if dep_idx != -1 else 0)
            if dep_idx != -1: self.load_employees_for_department()
            emp_idx = self.employee_fio_combo.findText(req.get("target_employee_fio", ""))
            self.employee_fio_combo.setCurrentIndex(emp_idx if emp_idx != -1 else 0)

            self.contact_last_name_edit.setText(req.get("contact_last_name", ""))
            self.contact_first_name_edit.setText(req.get("contact_first_name", ""))
            # Populate other contact fields if they were added to UI

            # Populate group visitors table (read-only for now)
            visitors = req.get("visitors", [])
            self.group_visitors_table_view.setRowCount(len(visitors))
            self.group_visitors_table_view.setColumnCount(7)  # Match creation form
            self.group_visitors_table_view.setHorizontalHeaderLabels(
                ["Фамилия", "Имя", "Отчество", "ДР", "Серия П.", "Номер П.", "Скан"])
            for i, v_data in enumerate(visitors):
                self.group_visitors_table_view.setItem(i, 0, QTableWidgetItem(v_data.get("last_name", "")))
                self.group_visitors_table_view.setItem(i, 1, QTableWidgetItem(v_data.get("first_name", "")))
                self.group_visitors_table_view.setItem(i, 2, QTableWidgetItem(v_data.get("patronymic", "")))
                self.group_visitors_table_view.setItem(i, 3, QTableWidgetItem(v_data.get("dob_str", "")))
                self.group_visitors_table_view.setItem(i, 4, QTableWidgetItem(v_data.get("passport_series", "")))
                self.group_visitors_table_view.setItem(i, 5, QTableWidgetItem(v_data.get("passport_number", "")))
                self.group_visitors_table_view.setItem(i, 6, QTableWidgetItem(
                    os.path.basename(v_data.get("passport_scan_path_saved", "Нет скана"))))
            self.group_visitors_table_view.resizeColumnsToContents()

    def handle_upload_visitor_photo_edit(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Новое фото посетителя", "", "Images (*.png *.jpg *.jpeg)")
        if filepath:
            is_valid, msg = validate_photo_or_scan(filepath, VISITOR_PHOTO_MAX_SIZE_MB, PHOTO_ASPECT_RATIO_W,
                                                   PHOTO_ASPECT_RATIO_H)
            if is_valid:
                self._newly_uploaded_visitor_photo = filepath  # Store path to new file
                pixmap = QPixmap(filepath)
                self.visitor_photo_label.setPixmap(
                    pixmap.scaled(PHOTO_PREVIEW_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                show_message(self, "Ошибка фото", msg, QMessageBox.Warning)
                self._newly_uploaded_visitor_photo = None  # Clear if invalid

    def handle_upload_scan_edit(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Новый скан паспорта", "", "JPG Images (*.jpg *.jpeg)")
        if filepath:
            is_valid, msg = validate_photo_or_scan(filepath, SCAN_MAX_SIZE_MB, is_scan=True)
            if is_valid:
                self._newly_uploaded_passport_scan = filepath  # Store path to new file
                self.scan_filename_label.setText(os.path.basename(filepath))
            else:
                show_message(self, "Ошибка скана", msg, QMessageBox.Warning)
                self._newly_uploaded_passport_scan = None

    def handle_save_changes(self):
        rd = self.request_data_edited  # Work on the copy

        if rd.get("request_type") == "individual":
            # --- Validation (similar to creation) ---
            required_fields_text = {
                "Цель посещения": self.visit_purpose_edit.text().strip(),
                "Фамилия посетителя": self.visitor_last_name_edit.text().strip(),
                "Имя посетителя": self.visitor_first_name_edit.text().strip(),
                "Примечание": self.visitor_note_edit.text().strip(),
                "E-mail": self.visitor_email_edit.text().strip(),
                "Серия паспорта": self.visitor_passport_series_edit.text().strip(),
                "Номер паспорта": self.visitor_passport_number_edit.text().strip(),
            }
            # Simplified validation for edit, assuming critical things like department/employee are chosen
            for name, value in required_fields_text.items():
                if not value:
                    show_message(self, "Ошибка валидации", f"Поле '{name}' не может быть пустым.", QMessageBox.Warning)
                    return
            if self.department_combo.currentIndex() == 0 or self.employee_fio_combo.currentIndex() == 0:
                show_message(self, "Ошибка валидации", "Подразделение и ФИО сотрудника должны быть выбраны.",
                             QMessageBox.Warning)
                return
            # Add other specific validations (email, passport, age) as in creation form
            if self.visitor_dob_edit.date().addYears(14) > QDate.currentDate():
                show_message(self, "Ошибка валидации", "Посетитель должен быть не моложе 14 лет.", QMessageBox.Warning)
                return
            if not re.match(r"[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,4}", self.visitor_email_edit.text().strip()):
                show_message(self, "Ошибка валидации", "Некорректный формат E-mail.", QMessageBox.Warning)
                return
            if not (
                    len(self.visitor_passport_series_edit.text()) == 4 and self.visitor_passport_series_edit.text().isdigit()):
                show_message(self, "Ошибка валидации", "Серия паспорта должна состоять из 4 цифр.",
                             QMessageBox.Warning);
                return
            if not (
                    len(self.visitor_passport_number_edit.text()) == 6 and self.visitor_passport_number_edit.text().isdigit()):
                show_message(self, "Ошибка валидации", "Номер паспорта должен состоять из 6 цифр.",
                             QMessageBox.Warning);
                return

            # --- Update fields in request_data_edited ---
            rd["visit_date_from"] = self.visit_date_from_edit.date().toString(Qt.ISODate)
            rd["visit_date_to"] = self.visit_date_to_edit.date().toString(Qt.ISODate)
            rd["visit_purpose"] = self.visit_purpose_edit.text().strip()
            rd["target_department"] = self.department_combo.currentText()
            rd["target_employee_fio"] = self.employee_fio_combo.currentText()
            rd["visitor_last_name"] = self.visitor_last_name_edit.text().strip()
            rd["visitor_first_name"] = self.visitor_first_name_edit.text().strip()
            rd["visitor_patronymic"] = self.visitor_patronymic_edit.text().strip()
            rd["visitor_phone"] = self.visitor_phone_edit.text()
            rd["visitor_email"] = self.visitor_email_edit.text().strip()
            rd["visitor_organization"] = self.visitor_organization_edit.text().strip()
            rd["visitor_note"] = self.visitor_note_edit.text().strip()
            rd["visitor_dob"] = self.visitor_dob_edit.date().toString(Qt.ISODate)
            rd["visitor_passport_series"] = self.visitor_passport_series_edit.text().strip()
            rd["visitor_passport_number"] = self.visitor_passport_number_edit.text().strip()

            # Handle file updates
            if self._newly_uploaded_visitor_photo:
                _, ext = os.path.splitext(self._newly_uploaded_visitor_photo)
                # Use original request_id for filename consistency if desired, or new UUID part
                new_photo_filename = f"visitor_{rd['request_id']}_edit{uuid4().hex[:4]}{ext}"
                dest_path = os.path.join(PHOTOS_DIR, new_photo_filename)
                try:
                    shutil.copy(self._newly_uploaded_visitor_photo, dest_path)
                    rd["visitor_photo_path"] = os.path.join("photos", new_photo_filename)
                except Exception as e:
                    show_message(self, "Ошибка", f"Не удалось сохранить новое фото: {e}", QMessageBox.Critical);
                    return

            if self._newly_uploaded_passport_scan:
                _, ext = os.path.splitext(self._newly_uploaded_passport_scan)
                new_scan_filename = f"scan_{rd['request_id']}_edit{uuid4().hex[:4]}{ext}"
                dest_path = os.path.join(SCANS_DIR, new_scan_filename)
                try:
                    shutil.copy(self._newly_uploaded_passport_scan, dest_path)
                    rd["passport_scan_path"] = os.path.join("scans", new_scan_filename)
                except Exception as e:
                    show_message(self, "Ошибка", f"Не удалось сохранить новый скан: {e}", QMessageBox.Critical);
                    return
            # If no new scan was uploaded, but original was missing, it remains missing unless logic is added to enforce it here.
            # For now, if _newly_uploaded_passport_scan is None, it means either original scan is kept, or no scan is present.
            # The TZ says scan is mandatory for individual. If it was missing, this edit should ideally not save without it.
            if not rd.get("passport_scan_path"):  # Check if a scan path exists after potential update
                show_message(self, "Ошибка валидации", "Скан паспорта обязателен. Пожалуйста, загрузите его.",
                             QMessageBox.Warning)
                return

        elif rd.get("request_type") == "group":
            # Update main group fields
            rd["visit_date_from"] = self.visit_date_from_edit.date().toString(Qt.ISODate)
            rd["visit_date_to"] = self.visit_date_to_edit.date().toString(Qt.ISODate)
            rd["visit_purpose"] = self.visit_purpose_edit.text().strip()
            rd["target_department"] = self.department_combo.currentText()
            rd["target_employee_fio"] = self.employee_fio_combo.currentText()
            rd["contact_last_name"] = self.contact_last_name_edit.text().strip()
            rd["contact_first_name"] = self.contact_first_name_edit.text().strip()
            # Update other contact fields if they were added to UI and rd
            # Visitor list itself is not edited here in this pass.

        else:
            show_message(self, "Ошибка", "Неизвестный тип заявки для сохранения.", QMessageBox.Critical)
            return

        # --- Save to JSON file ---
        all_requests = load_json(PASS_REQUESTS_FILE)
        updated = False
        for i, req_item in enumerate(all_requests):
            if req_item.get("request_id") == rd.get("request_id"):
                all_requests[i] = rd  # Replace with edited data
                updated = True
                break

        if updated:
            save_json(PASS_REQUESTS_FILE, all_requests)
            show_message(self, "Успех", "Изменения в заявке сохранены.")
            if self.parent_window and hasattr(self.parent_window, 'load_pending_requests'):
                self.parent_window.load_pending_requests()  # Refresh parent table
            self.accept()  # Close dialog
        else:
            show_message(self, "Ошибка сохранения", "Не удалось найти заявку для обновления.", QMessageBox.Critical)


# --- Admin Request Review Window ---
class AdminRequestReviewWindow(BaseWindow):
    def __init__(self, current_user_info, main_app_controller, parent_dashboard=None):
        super().__init__(current_user_info)
        self.main_app_controller = main_app_controller
        self.parent_dashboard = parent_dashboard
        self.setWindowTitle("Стражник - Обработка заявок на пропуск")
        self.setMinimumSize(800, 600)
        self.init_ui()
        self._create_status_bar_with_user()
        self.load_pending_requests()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        title_label = QLabel("Список заявок на рассмотрении")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title_label)

        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(6)
        self.requests_table.setHorizontalHeaderLabels(
            ["ID Заявки", "Посетитель (ФИО)", "Тип", "Подразделение", "Дата с", "Статус"])
        self.requests_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.requests_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.requests_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.requests_table.itemDoubleClicked.connect(
            self.open_edit_request_dialog)  # Changed from view_request_details
        layout.addWidget(self.requests_table)

        buttons_layout = QHBoxLayout()
        self.edit_button = QPushButton("Редактировать заявку")  # New Edit button
        self.edit_button.clicked.connect(self.open_edit_request_dialog_from_button)
        buttons_layout.addWidget(self.edit_button)

        buttons_layout.addSpacing(20)  # Spacer

        self.approve_button = QPushButton("Одобрить")
        self.approve_button.clicked.connect(self.approve_selected_request)
        buttons_layout.addWidget(self.approve_button)

        self.reject_button = QPushButton("Отклонить")
        self.reject_button.clicked.connect(self.reject_selected_request)
        buttons_layout.addWidget(self.reject_button)

        self.refresh_button = QPushButton("Обновить список")
        self.refresh_button.clicked.connect(self.load_pending_requests)
        buttons_layout.addWidget(self.refresh_button)

        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)

    def load_pending_requests(self):
        self.requests_table.setRowCount(0)
        all_requests = load_json(PASS_REQUESTS_FILE)
        # Displaying 'pending_review' and also 'approved'/'rejected' for admin to see all.
        # Or filter as per TZ "Список заявок на рассмотрении" implies only pending.
        # Let's stick to pending_review for this view.
        pending_requests = [req for req in all_requests if req.get("status") == "pending_review"]

        for req_data in pending_requests:
            row_position = self.requests_table.rowCount()
            self.requests_table.insertRow(row_position)

            visitor_name = f"{req_data.get('visitor_last_name', '')} {req_data.get('visitor_first_name', '')[:1]}."
            if req_data.get('visitor_patronymic'):
                visitor_name += f"{req_data.get('visitor_patronymic')[:1]}."
            if req_data.get("request_type") == "group":  # For group, main contact is in contact_ fields
                visitor_name = f"{req_data.get('contact_last_name', '')} {req_data.get('contact_first_name', '')[:1]}. (Группа)"

            self.requests_table.setItem(row_position, 0, QTableWidgetItem(req_data.get("request_id", "N/A")))
            self.requests_table.setItem(row_position, 1, QTableWidgetItem(visitor_name))
            self.requests_table.setItem(row_position, 2, QTableWidgetItem(req_data.get("request_type", "N/A")))
            self.requests_table.setItem(row_position, 3, QTableWidgetItem(req_data.get("target_department", "N/A")))
            self.requests_table.setItem(row_position, 4, QTableWidgetItem(req_data.get("visit_date_from", "N/A")))
            self.requests_table.setItem(row_position, 5, QTableWidgetItem("На рассмотрении"))
            self.requests_table.item(row_position, 0).setData(Qt.UserRole, req_data)

    def get_selected_request_data(self):
        current_row = self.requests_table.currentRow()
        if current_row < 0:
            # show_message(self, "Ошибка", "Пожалуйста, выберите заявку из списка.", QMessageBox.Warning) # Commented out to allow button click without selection for now
            return None
        request_id_item = self.requests_table.item(current_row, 0)
        if not request_id_item: return None
        return request_id_item.data(Qt.UserRole)

    def open_edit_request_dialog(self, item=None):  # Triggered by double-click or button
        request_data = self.get_selected_request_data()
        if request_data:
            if request_data.get("request_type") == "individual":
                edit_dialog = EditRequestDialog(request_data, self.current_user_info, self)
                edit_dialog.exec_()  # exec_ makes it modal
            elif request_data.get("request_type") == "group":
                # For now, group editing is simplified or uses the same dialog with limited fields
                edit_dialog = EditRequestDialog(request_data, self.current_user_info, self)
                edit_dialog.exec_()
                # show_message(self, "Редактирование группы", "Редактирование групповых заявок будет доработано. Пока доступны основные поля.", QMessageBox.INFORMATION)
            else:
                show_message(self, "Ошибка", "Неизвестный тип заявки для редактирования.", QMessageBox.Warning)
        else:
            show_message(self, "Действие", "Пожалуйста, выберите заявку для редактирования.", QMessageBox.Information)

    def open_edit_request_dialog_from_button(self):
        self.open_edit_request_dialog()  # Call the same method

    def update_request_status(self, request_id, new_status, reason=""):
        all_requests = load_json(PASS_REQUESTS_FILE)
        updated = False
        for req in all_requests:
            if req.get("request_id") == request_id:
                req["status"] = new_status
                if new_status == "rejected" and reason:
                    req["rejection_reason"] = reason
                elif new_status == "approved":
                    req.pop("rejection_reason", None)
                updated = True
                break
        if updated:
            save_json(PASS_REQUESTS_FILE, all_requests)
            show_message(self, "Успех", f"Статус заявки {request_id} обновлен на '{new_status}'.")
            self.load_pending_requests()
        else:
            show_message(self, "Ошибка", f"Заявка {request_id} не найдена.", QMessageBox.Critical)

    def approve_selected_request(self):
        request_data = self.get_selected_request_data()
        if request_data:
            if request_data.get("status") != "pending_review":
                show_message(self, "Информация", "Эта заявка уже обработана.", QMessageBox.Information)
                return
            reply = QMessageBox.question(self, "Подтверждение", f"Одобрить заявку {request_data.get('request_id')}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.update_request_status(request_data.get('request_id'), "approved")
        else:
            show_message(self, "Действие", "Пожалуйста, выберите заявку для одобрения.", QMessageBox.Information)

    def reject_selected_request(self):
        request_data = self.get_selected_request_data()
        if request_data:
            if request_data.get("status") != "pending_review":
                show_message(self, "Информация", "Эта заявка уже обработана.", QMessageBox.Information)
                return
            # TODO: Implement a proper dialog to get rejection reason.
            # For now, use a simple input or a fixed reason.
            # from PyQt5.QtWidgets import QInputDialog
            # reason, ok = QInputDialog.getText(self, 'Причина отказа', 'Укажите причину отклонения заявки:')
            # if ok: # If user provided a reason
            #    if not reason.strip(): reason = "Причина не указана администратором."
            # else: # User cancelled the input dialog
            #    return

            reply = QMessageBox.question(self, "Подтверждение", f"Отклонить заявку {request_data.get('request_id')}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.update_request_status(request_data.get('request_id'), "rejected",
                                           reason="Отклонено администратором (детализация причины в разработке)")
        else:
            show_message(self, "Действие", "Пожалуйста, выберите заявку для отклонения.", QMessageBox.Information)

    def closeEvent(self, event):
        if self.parent_dashboard:
            self.parent_dashboard.show()
        super().closeEvent(event)


# --- Security Service Main Window ---
class SecurityMainWindow(BaseWindow):
    def __init__(self, current_user_info, main_app_controller):
        super().__init__(current_user_info)
        self.main_app_controller = main_app_controller
        self.setWindowTitle("Стражник - Панель сотрудника СБ")
        self.setMinimumSize(800, 600)
        self.init_ui()
        self._create_status_bar_with_user()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        label = QLabel("Панель сотрудника службы безопасности")
        label.setFont(QFont("Arial", 16, QFont.Bold))
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        layout.addSpacing(20)

        pass_request_button = QPushButton("Оформить заявку на пропуск")
        pass_request_button.clicked.connect(self.open_pass_request_type_selection)
        layout.addWidget(pass_request_button)

        layout.addStretch()
        logout_button = QPushButton("Выход из системы")
        logout_button.clicked.connect(self.handle_logout)
        layout.addWidget(logout_button, alignment=Qt.AlignRight)

    def open_pass_request_type_selection(self):
        self.pass_type_window = SecurityPassTypeSelectionWindow(self.current_user_info, self.main_app_controller, self)
        self.pass_type_window.exec_()

    def handle_logout(self):
        self.main_app_controller.show_login_window()
        self.close()


# --- Security Pass Type Selection Window (Fig. 3) ---
class SecurityPassTypeSelectionWindow(QDialog):
    def __init__(self, current_user_info, main_app_controller, parent=None):
        super().__init__(parent)
        self.current_user_info = current_user_info
        self.main_app_controller = main_app_controller
        self.setWindowTitle("Стражник - Выбор типа заявки")
        self.setMinimumSize(450, 300)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        user_name_display = QLabel(get_fio_short(self.current_user_info.get("full_name", "")))
        user_name_display.setAlignment(Qt.AlignRight)
        user_name_display.setStyleSheet("font-weight: bold; padding-bottom: 10px;")
        main_layout.addWidget(user_name_display)

        logo_label = QLabel("ККОТИП")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setFont(QFont("Arial", 10, QFont.Bold))
        logo_label.setStyleSheet("color: #888; border: 1px dashed #ccc; padding: 10px;")
        logo_label.setMinimumHeight(50)
        main_layout.addWidget(logo_label)
        main_layout.addSpacing(10)

        title_label = QLabel("Выберите тип посещения:")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(30)
        buttons_layout.setAlignment(Qt.AlignCenter)

        self.individual_visit_button = QPushButton("Личное\nпосещение")
        self.individual_visit_button.setIconSize(QSize(48, 48))
        self.individual_visit_button.setMinimumSize(150, 100)
        self.individual_visit_button.clicked.connect(self.open_individual_request_form)
        buttons_layout.addWidget(self.individual_visit_button)

        self.group_visit_button = QPushButton("Групповое\nпосещение")
        self.group_visit_button.setIconSize(QSize(48, 48))
        self.group_visit_button.setMinimumSize(150, 100)
        self.group_visit_button.clicked.connect(self.open_group_request_form)
        buttons_layout.addWidget(self.group_visit_button)

        main_layout.addLayout(buttons_layout)
        main_layout.addStretch()

    def open_individual_request_form(self):
        self.accept()
        if self.parent():
            # Ensure parent is SecurityMainWindow and has this attribute defined
            if isinstance(self.parent(), SecurityMainWindow):
                self.parent().individual_pass_form = SecurityIndividualPassRequestWindow(self.current_user_info,
                                                                                         self.main_app_controller,
                                                                                         self.parent())
                self.parent().individual_pass_form.show()

    def open_group_request_form(self):
        self.accept()
        if self.parent():
            if isinstance(self.parent(), SecurityMainWindow):
                self.parent().group_pass_form = SecurityGroupPassRequestWindow(self.current_user_info,
                                                                               self.main_app_controller, self.parent())
                self.parent().group_pass_form.show()


# --- Security Individual Pass Request Window (Fig. 4) ---
class SecurityIndividualPassRequestWindow(BaseWindow):
    def __init__(self, current_user_info, main_app_controller, parent=None):
        super().__init__(current_user_info, parent)
        self.main_app_controller = main_app_controller
        self.setWindowTitle("Стражник - Заявка на личное посещение")
        self.setMinimumSize(700, 750)
        self.selected_visitor_photo_path = None
        self.selected_passport_scan_path = None
        self.init_ui()
        self._create_status_bar_with_user()

    def _create_styled_groupbox(self, title):
        group_box = QGroupBox(title)
        group_box.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 1px solid #FF8C00; border-radius: 5px; margin-top: 1ex; background-color: #FFF5E6; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; background-color: #FF8C00; color: white; border-radius: 3px; }
        """)
        return group_box

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_scroll = QScrollArea()
        main_scroll.setWidgetResizable(True)
        scroll_content_widget = QWidget()
        main_scroll.setWidget(scroll_content_widget)

        layout = QVBoxLayout(scroll_content_widget)
        logo_label = QLabel("ЛОГОТИП КОМПАНИИ")
        logo_label.setAlignment(Qt.AlignLeft)
        logo_label.setFont(QFont("Arial", 10, QFont.Bold))
        logo_label.setStyleSheet("color: #888; padding: 10px;")
        layout.addWidget(logo_label)

        title_label = QLabel("Форма записи на посещение мероприятия")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        layout.addSpacing(15)

        top_grid = QGridLayout()
        pass_info_group = self._create_styled_groupbox("Информация для пропуска")
        pass_info_layout = QGridLayout(pass_info_group)
        pass_info_layout.addWidget(QLabel("Срок действия заявки: c*"), 0, 0)
        self.visit_date_from_edit = QDateEdit(calendarPopup=True)
        self.visit_date_from_edit.setDate(QDate.currentDate().addDays(1))
        self.visit_date_from_edit.setMinimumDate(QDate.currentDate().addDays(1))
        self.visit_date_from_edit.setMaximumDate(QDate.currentDate().addDays(15))
        self.visit_date_from_edit.dateChanged.connect(self._update_date_to_min)
        pass_info_layout.addWidget(self.visit_date_from_edit, 0, 1)
        pass_info_layout.addWidget(QLabel("по*"), 0, 2)
        self.visit_date_to_edit = QDateEdit(calendarPopup=True)
        self._update_date_to_min()
        pass_info_layout.addWidget(self.visit_date_to_edit, 0, 3)
        pass_info_layout.addWidget(QLabel("Цель посещения*:"), 1, 0)
        self.visit_purpose_edit = QLineEdit()
        self.visit_purpose_edit.setPlaceholderText("Например, встреча, собеседование")
        pass_info_layout.addWidget(self.visit_purpose_edit, 1, 1, 1, 3)
        top_grid.addWidget(pass_info_group, 0, 0)

        receiving_party_group = self._create_styled_groupbox("Принимающая сторона")
        receiving_party_layout = QGridLayout(receiving_party_group)
        receiving_party_layout.addWidget(QLabel("Подразделение*:"), 0, 0)
        self.department_combo = QComboBox()
        self.load_departments()
        self.department_combo.currentIndexChanged.connect(self.load_employees_for_department)
        receiving_party_layout.addWidget(self.department_combo, 0, 1)
        receiving_party_layout.addWidget(QLabel("ФИО сотрудника*:"), 1, 0)
        self.employee_fio_combo = QComboBox()
        receiving_party_layout.addWidget(self.employee_fio_combo, 1, 1)
        top_grid.addWidget(receiving_party_group, 0, 1)
        layout.addLayout(top_grid)

        visitor_info_group = self._create_styled_groupbox("Информация о посетителе")
        visitor_info_layout = QGridLayout(visitor_info_group)
        visitor_info_layout.addWidget(QLabel("Фамилия*:"), 0, 0)
        self.visitor_last_name_edit = QLineEdit()
        visitor_info_layout.addWidget(self.visitor_last_name_edit, 0, 1)
        visitor_info_layout.addWidget(QLabel("Организация:"), 0, 2)
        self.visitor_organization_edit = QLineEdit()
        visitor_info_layout.addWidget(self.visitor_organization_edit, 0, 3)
        visitor_info_layout.addWidget(QLabel("Имя*:"), 1, 0)
        self.visitor_first_name_edit = QLineEdit()
        visitor_info_layout.addWidget(self.visitor_first_name_edit, 1, 1)
        visitor_info_layout.addWidget(QLabel("Примечание*:"), 1, 2)
        self.visitor_note_edit = QLineEdit()
        visitor_info_layout.addWidget(self.visitor_note_edit, 1, 3)
        visitor_info_layout.addWidget(QLabel("Отчество:"), 2, 0)
        self.visitor_patronymic_edit = QLineEdit()
        visitor_info_layout.addWidget(self.visitor_patronymic_edit, 2, 1)
        visitor_info_layout.addWidget(QLabel("Дата рождения*:"), 2, 2)
        self.visitor_dob_edit = QDateEdit(calendarPopup=True)
        self.visitor_dob_edit.setMaximumDate(QDate.currentDate().addYears(-14))
        self.visitor_dob_edit.setDate(QDate.currentDate().addYears(-25))
        visitor_info_layout.addWidget(self.visitor_dob_edit, 2, 3)
        visitor_info_layout.addWidget(QLabel("Телефон:"), 3, 0)
        self.visitor_phone_edit = QLineEdit()
        self.visitor_phone_edit.setInputMask("+7 (999) 999-99-99;_")
        visitor_info_layout.addWidget(self.visitor_phone_edit, 3, 1)
        visitor_info_layout.addWidget(QLabel("Серия паспорта*:"), 3, 2)
        self.visitor_passport_series_edit = QLineEdit()
        self.visitor_passport_series_edit.setMaxLength(4)
        self.visitor_passport_series_edit.setValidator(QRegExpValidator(QRegExp("\\d{4}")))
        visitor_info_layout.addWidget(self.visitor_passport_series_edit, 3, 3)
        visitor_info_layout.addWidget(QLabel("E-mail*:"), 4, 0)
        self.visitor_email_edit = QLineEdit()
        self.visitor_email_edit.setValidator(QRegExpValidator(QRegExp("[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,4}")))
        visitor_info_layout.addWidget(self.visitor_email_edit, 4, 1)
        visitor_info_layout.addWidget(QLabel("Номер паспорта*:"), 4, 2)
        self.visitor_passport_number_edit = QLineEdit()
        self.visitor_passport_number_edit.setMaxLength(6)
        self.visitor_passport_number_edit.setValidator(QRegExpValidator(QRegExp("\\d{6}")))
        visitor_info_layout.addWidget(self.visitor_passport_number_edit, 4, 3)

        self.visitor_photo_label = QLabel("Фото посетителя\n(3x4, опционально)")
        self.visitor_photo_label.setFixedSize(PHOTO_PREVIEW_SIZE)
        self.visitor_photo_label.setAlignment(Qt.AlignCenter)
        self.visitor_photo_label.setStyleSheet("border: 1px solid #ccc; background-color: #f0f0f0;")
        visitor_info_layout.addWidget(self.visitor_photo_label, 0, 4, 3, 1, Qt.AlignTop | Qt.AlignCenter)
        self.upload_visitor_photo_button = QPushButton("Загрузить фото")
        self.upload_visitor_photo_button.clicked.connect(self.handle_upload_visitor_photo)
        visitor_info_layout.addWidget(self.upload_visitor_photo_button, 3, 4, Qt.AlignTop | Qt.AlignCenter)
        layout.addWidget(visitor_info_group)

        docs_group = self._create_styled_groupbox("Прикрепляемые документы")
        docs_layout = QHBoxLayout(docs_group)
        self.upload_scan_button = QPushButton("Прикрепить скан паспорта (JPG)*")
        self.upload_scan_button.clicked.connect(self.handle_upload_scan)
        self.scan_filename_label = QLabel("Файл не выбран")
        docs_layout.addWidget(self.upload_scan_button)
        docs_layout.addWidget(self.scan_filename_label)
        docs_layout.addStretch()
        layout.addWidget(docs_group)
        layout.addStretch(1)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.clear_form_button = QPushButton("Очистить форму")
        self.clear_form_button.clicked.connect(self.clear_form_fields)
        button_layout.addWidget(self.clear_form_button)
        self.submit_button = QPushButton("Оформить заявку")
        self.submit_button.setStyleSheet("background-color: #FFA500; color: white; font-weight: bold;")
        self.submit_button.clicked.connect(self.handle_submit_request)
        button_layout.addWidget(self.submit_button)
        layout.addLayout(button_layout)

        outer_layout = QVBoxLayout(central_widget)
        outer_layout.addWidget(main_scroll)

    def _update_date_to_min(self):
        min_date_to = self.visit_date_from_edit.date()
        max_date_to = self.visit_date_from_edit.date().addDays(14)
        current_max_overall = QDate.currentDate().addDays(15)
        if max_date_to > current_max_overall: max_date_to = current_max_overall
        self.visit_date_to_edit.setMinimumDate(min_date_to)
        self.visit_date_to_edit.setMaximumDate(max_date_to)
        if self.visit_date_to_edit.date() < min_date_to: self.visit_date_to_edit.setDate(min_date_to)

    def load_departments(self):
        employees_data = load_json(EMPLOYEES_FILE)
        departments = sorted(list(set(emp.get("department", "Не указано") for emp in employees_data)))
        self.department_combo.clear()
        self.department_combo.addItem("Выберите подразделение")
        self.department_combo.addItems(departments)

    def load_employees_for_department(self):
        selected_department = self.department_combo.currentText()
        self.employee_fio_combo.clear()
        self.employee_fio_combo.addItem("Выберите сотрудника")
        if selected_department != "Выберите подразделение" and selected_department != "":  # Check against empty string too
            employees_data = load_json(EMPLOYEES_FILE)
            department_employees = [
                f"{emp['last_name']} {emp['first_name']} {emp.get('patronymic', '')}".strip()
                for emp in employees_data if emp.get("department") == selected_department
            ]
            self.employee_fio_combo.addItems(sorted(department_employees))

    def handle_upload_visitor_photo(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Фото посетителя", "", "Images (*.png *.jpg *.jpeg)")
        if filepath:
            is_valid, msg = validate_photo_or_scan(filepath, VISITOR_PHOTO_MAX_SIZE_MB, PHOTO_ASPECT_RATIO_W,
                                                   PHOTO_ASPECT_RATIO_H)
            if is_valid:
                self.selected_visitor_photo_path = filepath
                pixmap = QPixmap(filepath)
                self.visitor_photo_label.setPixmap(
                    pixmap.scaled(PHOTO_PREVIEW_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                show_message(self, "Ошибка фото", msg, QMessageBox.Warning)
                self.selected_visitor_photo_path = None
                self.visitor_photo_label.setText("Фото не\nсоответствует")
                self.visitor_photo_label.setPixmap(QPixmap())

    def handle_upload_scan(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Скан паспорта", "", "JPG Images (*.jpg *.jpeg)")
        if filepath:
            is_valid, msg = validate_photo_or_scan(filepath, SCAN_MAX_SIZE_MB, is_scan=True)
            if is_valid:
                self.selected_passport_scan_path = filepath
                self.scan_filename_label.setText(os.path.basename(filepath))
            else:
                show_message(self, "Ошибка скана", msg, QMessageBox.Warning)
                self.selected_passport_scan_path = None
                self.scan_filename_label.setText("Файл не соответствует")

    def clear_form_fields(self):
        self.visit_date_from_edit.setDate(QDate.currentDate().addDays(1))
        self._update_date_to_min()
        self.visit_purpose_edit.clear()
        self.department_combo.setCurrentIndex(0)
        self.visitor_last_name_edit.clear()
        self.visitor_first_name_edit.clear()
        self.visitor_patronymic_edit.clear()
        self.visitor_organization_edit.clear()
        self.visitor_note_edit.clear()
        self.visitor_dob_edit.setDate(QDate.currentDate().addYears(-25))
        self.visitor_phone_edit.clear()
        self.visitor_email_edit.clear()
        self.visitor_passport_series_edit.clear()
        self.visitor_passport_number_edit.clear()
        self.selected_visitor_photo_path = None
        self.visitor_photo_label.setText("Фото посетителя\n(3x4, опционально)")
        self.visitor_photo_label.setPixmap(QPixmap())
        self.selected_passport_scan_path = None
        self.scan_filename_label.setText("Файл не выбран")

    def handle_submit_request(self):
        required_fields_text = {
            "Срок действия (с)": self.visit_date_from_edit.date(),
            "Срок действия (по)": self.visit_date_to_edit.date(),
            "Цель посещения": self.visit_purpose_edit.text().strip(),
            "Подразделение": self.department_combo.currentText(),
            "ФИО сотрудника": self.employee_fio_combo.currentText(),
            "Фамилия посетителя": self.visitor_last_name_edit.text().strip(),
            "Имя посетителя": self.visitor_first_name_edit.text().strip(),
            "Примечание": self.visitor_note_edit.text().strip(),
            "Дата рождения": self.visitor_dob_edit.date(),
            "E-mail": self.visitor_email_edit.text().strip(),
            "Серия паспорта": self.visitor_passport_series_edit.text().strip(),
            "Номер паспорта": self.visitor_passport_number_edit.text().strip(),
        }
        for name, value in required_fields_text.items():
            if isinstance(value, str) and (not value or value.startswith("Выберите")):
                show_message(self, "Ошибка валидации", f"Поле '{name}' обязательно для заполнения.",
                             QMessageBox.Warning)
                return
        if self.visit_date_from_edit.date() > self.visit_date_to_edit.date():
            show_message(self, "Ошибка валидации", "Дата начала не может быть позже даты окончания.",
                         QMessageBox.Warning)
            return
        if self.visitor_dob_edit.date().addYears(14) > QDate.currentDate():
            show_message(self, "Ошибка валидации", "Посетитель должен быть не моложе 14 лет.", QMessageBox.Warning)
            return
        if not re.match(r"[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,4}", self.visitor_email_edit.text().strip()):
            show_message(self, "Ошибка валидации", "Некорректный формат E-mail.", QMessageBox.Warning)
            return
        if not (
                len(self.visitor_passport_series_edit.text()) == 4 and self.visitor_passport_series_edit.text().isdigit()):
            show_message(self, "Ошибка валидации", "Серия паспорта должна состоять из 4 цифр.", QMessageBox.Warning)
            return
        if not (
                len(self.visitor_passport_number_edit.text()) == 6 and self.visitor_passport_number_edit.text().isdigit()):
            show_message(self, "Ошибка валидации", "Номер паспорта должен состоять из 6 цифр.", QMessageBox.Warning)
            return
        if not self.selected_passport_scan_path:
            show_message(self, "Ошибка валидации", "Необходимо прикрепить скан паспорта.", QMessageBox.Warning)
            return

        request_id = str(uuid4())
        visitor_photo_savename = None
        if self.selected_visitor_photo_path:
            _, ext = os.path.splitext(self.selected_visitor_photo_path)
            visitor_photo_savename = f"visitor_{request_id}{ext}"
            try:
                shutil.copy(self.selected_visitor_photo_path, os.path.join(PHOTOS_DIR, visitor_photo_savename))
                visitor_photo_savename = os.path.join("photos", visitor_photo_savename)
            except Exception as e:
                show_message(self, "Ошибка сохранения фото", f"Не удалось сохранить фото посетителя: {e}",
                             QMessageBox.Critical)
                return

        _, scan_ext = os.path.splitext(self.selected_passport_scan_path)
        passport_scan_savename = f"scan_{request_id}{scan_ext}"
        try:
            shutil.copy(self.selected_passport_scan_path, os.path.join(SCANS_DIR, passport_scan_savename))
            passport_scan_savename = os.path.join("scans", passport_scan_savename)
        except Exception as e:
            show_message(self, "Ошибка сохранения скана", f"Не удалось сохранить скан паспорта: {e}",
                         QMessageBox.Critical)
            return

        request_data = {
            "request_id": request_id, "request_type": "individual",
            "submission_date": datetime.now().isoformat(),
            "submitted_by_user": self.current_user_info.get("login"),
            "visit_date_from": self.visit_date_from_edit.date().toString(Qt.ISODate),
            "visit_date_to": self.visit_date_to_edit.date().toString(Qt.ISODate),
            "visit_purpose": self.visit_purpose_edit.text().strip(),
            "target_department": self.department_combo.currentText(),
            "target_employee_fio": self.employee_fio_combo.currentText(),
            "visitor_last_name": self.visitor_last_name_edit.text().strip(),
            "visitor_first_name": self.visitor_first_name_edit.text().strip(),
            "visitor_patronymic": self.visitor_patronymic_edit.text().strip(),
            "visitor_phone": self.visitor_phone_edit.text(),
            "visitor_email": self.visitor_email_edit.text().strip(),
            "visitor_organization": self.visitor_organization_edit.text().strip(),
            "visitor_note": self.visitor_note_edit.text().strip(),
            "visitor_dob": self.visitor_dob_edit.date().toString(Qt.ISODate),
            "visitor_passport_series": self.visitor_passport_series_edit.text().strip(),
            "visitor_passport_number": self.visitor_passport_number_edit.text().strip(),
            "visitor_photo_path": visitor_photo_savename,
            "passport_scan_path": passport_scan_savename,
            "status": "pending_review"
        }
        all_requests = load_json(PASS_REQUESTS_FILE)
        all_requests.append(request_data)
        save_json(PASS_REQUESTS_FILE, all_requests)
        show_message(self, "Успех", f"Заявка {request_id} успешно оформлена и отправлена на рассмотрение.")
        self.clear_form_fields()
        self.close()

    # --- Security Group Pass Request Window (Fig. 5) ---


class SecurityGroupPassRequestWindow(BaseWindow):
    def __init__(self, current_user_info, main_app_controller, parent=None):
        super().__init__(current_user_info, parent)
        self.main_app_controller = main_app_controller
        self.setWindowTitle("Стражник - Заявка на групповое посещение")
        self.setMinimumSize(800, 700)
        self.group_list_data = []
        self.group_list_filepath = None
        self.init_ui()
        self._create_status_bar_with_user()

    def _create_styled_groupbox(self, title):
        group_box = QGroupBox(title)
        group_box.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 1px solid #FF8C00; border-radius: 5px; margin-top: 1ex; background-color: #FFF5E6; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; background-color: #FF8C00; color: white; border-radius: 3px; }
        """)
        return group_box

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_scroll = QScrollArea()
        main_scroll.setWidgetResizable(True)
        scroll_content_widget = QWidget()
        main_scroll.setWidget(scroll_content_widget)
        layout = QVBoxLayout(scroll_content_widget)

        logo_label = QLabel("ЛОГОТИП КОМПАНИИ")
        logo_label.setAlignment(Qt.AlignLeft)
        logo_label.setFont(QFont("Arial", 10, QFont.Bold))
        logo_label.setStyleSheet("color: #888; padding: 10px;")
        layout.addWidget(logo_label)

        title_label = QLabel("Форма записи на групповое посещение")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        layout.addSpacing(15)

        top_grid = QGridLayout()
        pass_info_group = self._create_styled_groupbox("Информация для пропуска")
        pass_info_layout = QGridLayout(pass_info_group)
        pass_info_layout.addWidget(QLabel("Срок действия заявки: c*"), 0, 0)
        self.visit_date_from_edit = QDateEdit(calendarPopup=True)
        self.visit_date_from_edit.setDate(QDate.currentDate().addDays(1))
        self.visit_date_from_edit.setMinimumDate(QDate.currentDate().addDays(1))
        self.visit_date_from_edit.setMaximumDate(QDate.currentDate().addDays(15))
        self.visit_date_from_edit.dateChanged.connect(self._update_date_to_min_group)
        pass_info_layout.addWidget(self.visit_date_from_edit, 0, 1)
        pass_info_layout.addWidget(QLabel("по*"), 0, 2)
        self.visit_date_to_edit = QDateEdit(calendarPopup=True)
        self._update_date_to_min_group()
        pass_info_layout.addWidget(self.visit_date_to_edit, 0, 3)
        pass_info_layout.addWidget(QLabel("Цель посещения*:"), 1, 0)
        self.visit_purpose_edit = QLineEdit()
        pass_info_layout.addWidget(self.visit_purpose_edit, 1, 1, 1, 3)
        top_grid.addWidget(pass_info_group, 0, 0)

        receiving_party_group = self._create_styled_groupbox("Принимающая сторона")
        receiving_party_layout = QGridLayout(receiving_party_group)
        receiving_party_layout.addWidget(QLabel("Подразделение*:"), 0, 0)
        self.department_combo = QComboBox()
        self.load_departments_group()
        self.department_combo.currentIndexChanged.connect(self.load_employees_for_department_group)
        receiving_party_layout.addWidget(self.department_combo, 0, 1)
        receiving_party_layout.addWidget(QLabel("ФИО сотрудника*:"), 1, 0)
        self.employee_fio_combo = QComboBox()
        receiving_party_layout.addWidget(self.employee_fio_combo, 1, 1)
        top_grid.addWidget(receiving_party_group, 0, 1)
        layout.addLayout(top_grid)

        group_contact_group = self._create_styled_groupbox("Контактное лицо группы (заявитель)")
        group_contact_layout = QGridLayout(group_contact_group)
        group_contact_layout.addWidget(QLabel("Фамилия*:"), 0, 0)
        self.contact_last_name_edit = QLineEdit()
        group_contact_layout.addWidget(self.contact_last_name_edit, 0, 1)
        group_contact_layout.addWidget(QLabel("Имя*:"), 0, 2)
        self.contact_first_name_edit = QLineEdit()
        group_contact_layout.addWidget(self.contact_first_name_edit, 0, 3)
        group_contact_layout.addWidget(QLabel("Телефон:"), 1, 0)
        self.contact_phone_edit = QLineEdit()
        self.contact_phone_edit.setInputMask("+7 (999) 999-99-99;_")
        group_contact_layout.addWidget(self.contact_phone_edit, 1, 1)
        group_contact_layout.addWidget(QLabel("E-mail*:"), 1, 2)
        self.contact_email_edit = QLineEdit()
        self.contact_email_edit.setValidator(QRegExpValidator(QRegExp("[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,4}")))
        group_contact_layout.addWidget(self.contact_email_edit, 1, 3)
        group_contact_layout.addWidget(QLabel("Организация:"), 2, 0)
        self.contact_organization_edit = QLineEdit()
        group_contact_layout.addWidget(self.contact_organization_edit, 2, 1)
        group_contact_layout.addWidget(QLabel("Примечание*:"), 2, 2)
        self.contact_note_edit = QLineEdit()
        group_contact_layout.addWidget(self.contact_note_edit, 2, 3)
        layout.addWidget(group_contact_group)

        visitor_list_group = self._create_styled_groupbox("Список посетителей")
        visitor_list_layout = QVBoxLayout(visitor_list_group)
        list_buttons_layout = QHBoxLayout()
        self.download_template_button = QPushButton("Скачать шаблон списка")
        self.download_template_button.clicked.connect(self.download_visitor_list_template)
        list_buttons_layout.addWidget(self.download_template_button)
        self.upload_list_button = QPushButton("Загрузить список (CSV/TXT)*")
        self.upload_list_button.clicked.connect(self.upload_visitor_list)
        list_buttons_layout.addWidget(self.upload_list_button)
        list_buttons_layout.addStretch()
        visitor_list_layout.addLayout(list_buttons_layout)
        self.group_list_table = QTableWidget()
        self.group_list_table.setColumnCount(7)
        self.group_list_table.setHorizontalHeaderLabels(
            ["Фамилия", "Имя", "Отчество", "ДР", "Серия П.", "Номер П.", "Скан Паспорта"])
        self.group_list_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.group_list_table.setMinimumHeight(150)
        visitor_list_layout.addWidget(self.group_list_table)
        layout.addWidget(visitor_list_group)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.clear_form_button_group = QPushButton("Очистить форму")
        self.clear_form_button_group.clicked.connect(self.clear_form_fields_group)
        button_layout.addWidget(self.clear_form_button_group)
        self.submit_button_group = QPushButton("Оформить заявку")
        self.submit_button_group.setStyleSheet("background-color: #FFA500; color: white; font-weight: bold;")
        self.submit_button_group.clicked.connect(self.handle_submit_group_request)
        button_layout.addWidget(self.submit_button_group)
        layout.addLayout(button_layout)

        outer_layout = QVBoxLayout(central_widget)
        outer_layout.addWidget(main_scroll)

    def _update_date_to_min_group(self):
        min_date_to = self.visit_date_from_edit.date()
        max_date_to = self.visit_date_from_edit.date().addDays(14)
        current_max_overall = QDate.currentDate().addDays(15)
        if max_date_to > current_max_overall: max_date_to = current_max_overall
        self.visit_date_to_edit.setMinimumDate(min_date_to)
        self.visit_date_to_edit.setMaximumDate(max_date_to)
        if self.visit_date_to_edit.date() < min_date_to: self.visit_date_to_edit.setDate(min_date_to)

    def load_departments_group(self):
        employees_data = load_json(EMPLOYEES_FILE)
        departments = sorted(list(set(emp.get("department", "Не указано") for emp in employees_data)))
        self.department_combo.clear()
        self.department_combo.addItem("Выберите подразделение")
        self.department_combo.addItems(departments)

    def load_employees_for_department_group(self):
        selected_department = self.department_combo.currentText()
        self.employee_fio_combo.clear()
        self.employee_fio_combo.addItem("Выберите сотрудника")
        if selected_department != "Выберите подразделение" and selected_department != "":
            employees_data = load_json(EMPLOYEES_FILE)
            department_employees = [
                f"{emp['last_name']} {emp['first_name']} {emp.get('patronymic', '')}".strip()
                for emp in employees_data if emp.get("department") == selected_department
            ]
            self.employee_fio_combo.addItems(sorted(department_employees))

    def download_visitor_list_template(self):
        template_filename = "group_visitor_template.csv"
        template_path = os.path.join(GROUP_LISTS_DIR, template_filename)
        template_content = "Фамилия*,Имя*,Отчество,ДатаРождения(ГГГГ-ММ-ДД)*,СерияПаспорта(4цифры)*,НомерПаспорта(6цифр)*,Телефон(+7...опц.),Email(опц.),Организация(опц.),ПутьКСкануПаспорта(JPG)*\n"
        try:
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(template_content)
            show_message(self, "Шаблон скачан",
                         f"Шаблон '{template_filename}' сохранен в папку {GROUP_LISTS_DIR}.\nПожалуйста, заполните его и загрузите. Каждый скан паспорта должен быть отдельным JPG файлом, путь к которому указывается в последней колонке (например, scans/visitor1_scan.jpg).")
        except Exception as e:
            show_message(self, "Ошибка", f"Не удалось сохранить шаблон: {e}", QMessageBox.Critical)

    def upload_visitor_list(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Загрузить список посетителей", GROUP_LISTS_DIR,
                                                  "CSV/TXT Files (*.csv *.txt)")
        if filepath:
            self.group_list_filepath = filepath
            self.group_list_data = []
            self.group_list_table.setRowCount(0)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if not lines:
                        show_message(self, "Ошибка", "Файл списка пуст.", QMessageBox.Warning);
                        return
                    for i, line in enumerate(lines[1:]):
                        if not line.strip(): continue
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) < 10:
                            show_message(self, "Ошибка в списке",
                                         f"Строка {i + 2}: недостаточно данных. Ожидается 10 колонок.",
                                         QMessageBox.Warning);
                            continue
                        visitor = {
                            "last_name": parts[0], "first_name": parts[1], "patronymic": parts[2],
                            "dob_str": parts[3], "passport_series": parts[4], "passport_number": parts[5],
                            "phone": parts[6], "email": parts[7], "organization": parts[8],
                            "scan_path_original": parts[9]
                        }
                        if not all([visitor["last_name"], visitor["first_name"], visitor["dob_str"],
                                    visitor["passport_series"], visitor["passport_number"],
                                    visitor["scan_path_original"]]):
                            show_message(self, "Ошибка в списке",
                                         f"Строка {i + 2}: не все обязательные поля (Фамилия, Имя, ДР, Серия, Номер, ПутьКСкану) заполнены.",
                                         QMessageBox.Warning);
                            continue
                        self.group_list_data.append(visitor)
                        row_pos = self.group_list_table.rowCount()
                        self.group_list_table.insertRow(row_pos)
                        self.group_list_table.setItem(row_pos, 0, QTableWidgetItem(visitor["last_name"]))
                        self.group_list_table.setItem(row_pos, 1, QTableWidgetItem(visitor["first_name"]))
                        self.group_list_table.setItem(row_pos, 2, QTableWidgetItem(visitor["patronymic"]))
                        self.group_list_table.setItem(row_pos, 3, QTableWidgetItem(visitor["dob_str"]))
                        self.group_list_table.setItem(row_pos, 4, QTableWidgetItem(visitor["passport_series"]))
                        self.group_list_table.setItem(row_pos, 5, QTableWidgetItem(visitor["passport_number"]))
                        self.group_list_table.setItem(row_pos, 6, QTableWidgetItem("Проверить"))
                if not self.group_list_data:
                    show_message(self, "Информация", "Список посетителей не содержит валидных записей.",
                                 QMessageBox.Information)
                else:
                    show_message(self, "Успех",
                                 f"Список из {len(self.group_list_data)} посетителей загружен. Проверьте данные.")
            except Exception as e:
                show_message(self, "Ошибка загрузки списка", f"Не удалось обработать файл: {e}", QMessageBox.Critical)
                self.group_list_data = [];
                self.group_list_table.setRowCount(0);
                self.group_list_filepath = None

    def clear_form_fields_group(self):
        self.visit_date_from_edit.setDate(QDate.currentDate().addDays(1))
        self._update_date_to_min_group()
        self.visit_purpose_edit.clear()
        self.department_combo.setCurrentIndex(0)
        self.contact_last_name_edit.clear()
        self.contact_first_name_edit.clear()
        self.contact_phone_edit.clear()
        self.contact_email_edit.clear()
        self.contact_organization_edit.clear()
        self.contact_note_edit.clear()
        self.group_list_data = []
        self.group_list_table.setRowCount(0)
        self.group_list_filepath = None

    def handle_submit_group_request(self):
        if not self.group_list_data:
            show_message(self, "Ошибка", "Список посетителей не загружен или пуст.", QMessageBox.Warning);
            return
        if not all([self.contact_last_name_edit.text().strip(), self.contact_first_name_edit.text().strip(),
                    self.contact_email_edit.text().strip(), self.contact_note_edit.text().strip()]):
            show_message(self, "Ошибка", "Заполните все обязательные поля для контактного лица группы.",
                         QMessageBox.Warning);
            return
        if not re.match(r"[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,4}", self.contact_email_edit.text().strip()):
            show_message(self, "Ошибка валидации", "Некорректный E-mail контактного лица.", QMessageBox.Warning);
            return
        if self.department_combo.currentIndex() == 0 or self.employee_fio_combo.currentIndex() == 0:
            show_message(self, "Ошибка", "Выберите подразделение и принимающего сотрудника.", QMessageBox.Warning);
            return

        processed_visitors = []
        for i, visitor_data_csv in enumerate(self.group_list_data):
            try:
                dob = QDate.fromString(visitor_data_csv["dob_str"], "yyyy-MM-dd")  # More specific format
                if not dob.isValid() or dob.addYears(16) > QDate.currentDate():
                    show_message(self, "Ошибка в списке",
                                 f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): дата рождения некорректна (ГГГГ-ММ-ДД) или возраст < 16 лет.",
                                 QMessageBox.Warning);
                    return
            except Exception:  # Broad exception for parsing
                show_message(self, "Ошибка в списке",
                             f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): неверный формат даты рождения (ожидается ГГГГ-ММ-ДД).",
                             QMessageBox.Warning);
                return
            if not (len(visitor_data_csv["passport_series"]) == 4 and visitor_data_csv["passport_series"].isdigit()):
                show_message(self, "Ошибка в списке",
                             f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): серия паспорта должна быть 4 цифры.",
                             QMessageBox.Warning);
                return
            if not (len(visitor_data_csv["passport_number"]) == 6 and visitor_data_csv["passport_number"].isdigit()):
                show_message(self, "Ошибка в списке",
                             f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): номер паспорта должен быть 6 цифр.",
                             QMessageBox.Warning);
                return

            original_scan_path = visitor_data_csv["scan_path_original"]
            resolved_scan_path = None
            if os.path.isabs(original_scan_path) and os.path.exists(original_scan_path):
                resolved_scan_path = original_scan_path
            elif self.group_list_filepath:
                potential_path_csv_relative = os.path.join(os.path.dirname(self.group_list_filepath),
                                                           original_scan_path)
                if os.path.exists(potential_path_csv_relative): resolved_scan_path = potential_path_csv_relative
            if not resolved_scan_path:
                potential_path_scans_dir = os.path.join(SCANS_DIR, os.path.basename(original_scan_path))
                if os.path.exists(potential_path_scans_dir):
                    resolved_scan_path = potential_path_scans_dir
                elif os.path.exists(os.path.join(DATA_DIR, original_scan_path)):
                    resolved_scan_path = os.path.join(DATA_DIR, original_scan_path)
            if not resolved_scan_path or not os.path.exists(resolved_scan_path):
                show_message(self, "Ошибка в списке",
                             f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): файл скана паспорта '{original_scan_path}' не найден.",
                             QMessageBox.Warning)
                self.group_list_table.item(i, 6).setText("Файл не найден!");
                self.group_list_table.item(i, 6).setBackground(QColor("red"));
                return
            is_valid_scan, scan_msg = validate_photo_or_scan(resolved_scan_path, SCAN_MAX_SIZE_MB, is_scan=True)
            if not is_valid_scan:
                show_message(self, "Ошибка в списке",
                             f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): скан паспорта '{original_scan_path}' не прошел валидацию: {scan_msg}",
                             QMessageBox.Warning)
                self.group_list_table.item(i, 6).setText("Ошибка валидации!");
                self.group_list_table.item(i, 6).setBackground(QColor("red"));
                return
            _, scan_ext = os.path.splitext(resolved_scan_path)
            visitor_id_for_scan = f"{visitor_data_csv['last_name']}_{visitor_data_csv['first_name']}_{i}"
            new_scan_filename = f"scan_group_{visitor_id_for_scan}_{uuid4().hex[:6]}{scan_ext}"
            destination_scan_path = os.path.join(SCANS_DIR, new_scan_filename)
            try:
                shutil.copy(resolved_scan_path, destination_scan_path)
                visitor_data_csv["passport_scan_path_saved"] = os.path.join("scans", new_scan_filename)
                self.group_list_table.item(i, 6).setText("OK");
                self.group_list_table.item(i, 6).setBackground(QColor("lightgreen"))
            except Exception as e:
                show_message(self, "Ошибка копирования скана",
                             f"Посетитель {i + 1} ({visitor_data_csv['last_name']}): не удалось скопировать скан '{original_scan_path}': {e}",
                             QMessageBox.Critical)
                self.group_list_table.item(i, 6).setText("Ошибка копирования!");
                self.group_list_table.item(i, 6).setBackground(QColor("red"));
                return
            processed_visitors.append(visitor_data_csv)

        request_id = str(uuid4())
        group_request_data = {
            "request_id": request_id, "request_type": "group", "submission_date": datetime.now().isoformat(),
            "submitted_by_user": self.current_user_info.get("login"),
            "visit_date_from": self.visit_date_from_edit.date().toString(Qt.ISODate),
            "visit_date_to": self.visit_date_to_edit.date().toString(Qt.ISODate),
            "visit_purpose": self.visit_purpose_edit.text().strip(),
            "target_department": self.department_combo.currentText(),
            "target_employee_fio": self.employee_fio_combo.currentText(),
            "contact_last_name": self.contact_last_name_edit.text().strip(),
            "contact_first_name": self.contact_first_name_edit.text().strip(),
            "contact_phone": self.contact_phone_edit.text(), "contact_email": self.contact_email_edit.text().strip(),
            "contact_organization": self.contact_organization_edit.text().strip(),
            "contact_note": self.contact_note_edit.text().strip(),
            "visitors": processed_visitors, "status": "pending_review"
        }
        group_request_data[
            "visitor_last_name"] = self.contact_last_name_edit.text().strip()  # For table display consistency
        group_request_data["visitor_first_name"] = self.contact_first_name_edit.text().strip()
        all_requests = load_json(PASS_REQUESTS_FILE)
        all_requests.append(group_request_data)
        save_json(PASS_REQUESTS_FILE, all_requests)
        show_message(self, "Успех", f"Групповая заявка {request_id} успешно оформлена и отправлена на рассмотрение.")
        self.clear_form_fields_group()
        self.close()


# --- Main Application Controller ---
class MainApplication:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.login_window = None
        self.admin_dashboard_window = None
        self.security_window = None
        self.current_user_info = None
        self.app.setStyleSheet("""
            QWidget { font-family: Arial, sans-serif; font-size: 10pt; }
            QPushButton { background-color: #5cb85c; color: white; border: 1px solid #4cae4c; padding: 8px 12px; border-radius: 4px; }
            QPushButton:hover { background-color: #4cae4c; }
            QPushButton:pressed { background-color: #449d44; }
            QLineEdit, QComboBox, QDateEdit, QTextEdit, QTableWidget { padding: 5px; border: 1px solid #ccc; border-radius: 3px; }
            QLabel { padding-bottom: 2px; }
            QGroupBox { margin-bottom: 10px; }
        """)

    def run(self):
        ensure_data_dirs_files()
        self.show_login_window()
        sys.exit(self.app.exec_())

    def show_login_window(self):
        if self.admin_dashboard_window: self.admin_dashboard_window.close(); self.admin_dashboard_window = None
        if self.security_window: self.security_window.close(); self.security_window = None
        self.current_user_info = None
        self.login_window = LoginWindow(self)
        self.login_window.show()

    def show_main_window(self, user_info):
        self.current_user_info = user_info
        if self.login_window: self.login_window.hide()
        if user_info["role"] == "admin":
            self.admin_dashboard_window = AdminDashboardWindow(user_info, self)
            self.admin_dashboard_window.show()
        elif user_info["role"] == "security":
            self.security_window = SecurityMainWindow(user_info, self)
            self.security_window.show()
        else:
            show_message(None, "Ошибка роли", "Неизвестная роль.", QMessageBox.Critical)
            self.show_login_window()


if __name__ == "__main__":
    controller = MainApplication()
    controller.run()
