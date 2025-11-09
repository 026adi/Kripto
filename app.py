import streamlit as st
import sqlite3
import os
import hashlib   # BLAKE2b
import numpy as np   # LSB
from PIL import Image, UnidentifiedImageError  # LSB
import io
import base64
import itertools   # XOR
import random      # <-- PERUBAHAN: Diperlukan untuk LSB Matching

# Req 2, 5, 7: Pustaka Kriptografi
from Crypto.Cipher import DES3, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# --- PENGATURAN DASAR ---
# Folder UPLOAD_FOLDER telah dihapus karena tidak digunakan
# (sesuai diskusi kita sebelumnya).
def load_css(file_name):
    """Membaca file CSS dan menyuntikkannya ke Streamlit."""
    try:
        # Mencoba membaca dan menyuntikkan CSS
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except FileNotFoundError:
        # Jika file CSS tidak ditemukan (misalnya di lingkungan yang berbeda), abaikan
        pass

def navigate_to(page):
    """Fungsi helper untuk navigasi"""
    st.session_state.current_page = page
    st.rerun()

# Panggil fungsi ini di awal main/router
load_css('style.css') # <-- DIPULIHKAN


# Session state
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Dashboard"

# --- KONEKSI DATABASE ---
def create_connection():
    try:
        connection = sqlite3.connect("pengaduan.db", check_same_thread=False)
        return connection
    except sqlite3.Error as e:
        st.error(f"Gagal terhubung ke database: {e}")
        return None



def derive_key(key_str, length):
    """Membuat kunci dengan panjang tetap dari string input."""
    hasher = SHA256.new(key_str.encode('utf-8'))
    return hasher.digest()[:length]


SALT_BYTES = 16
HASH_BYTES = 32  

def hash_password(password):
    """Membuat hash password menggunakan BLAKE2b + salt."""
    salt = os.urandom(SALT_BYTES)
    h = hashlib.blake2b(digest_size=HASH_BYTES)
    h.update(salt + password.encode('utf-8'))
    hashed_password_bytes = salt + h.digest()
    # Simpan sebagai string Base64
    return base64.b64encode(hashed_password_bytes).decode('utf-8')

def check_password(password, hashed_password):
    """Memverifikasi password terhadap hash BLAKE2b + salt."""
    try:
        # Decode string Base64 kembali ke bytes
        hashed_password_bytes = base64.b64decode(hashed_password.encode('utf-8'))
        
        # Ekstrak salt dan hash yang disimpan
        salt = hashed_password_bytes[:SALT_BYTES]
        stored_hash = hashed_password_bytes[SALT_BYTES:]

        # Pastikan hash yang disimpan memiliki panjang yang diharapkan
        if len(stored_hash) != HASH_BYTES:
            return False

        # Buat hash baru menggunakan password dan salt yang diekstrak
        h_check = hashlib.blake2b(digest_size=HASH_BYTES)
        h_check.update(salt + password.encode('utf-8'))
        
        # --- PERUBAHAN DI SINI ---
        # Dikembalikan ke metode pbkdf2_hmac untuk kompatibilitas Python lama.
        # Ini adalah trik perbandingan aman yang berfungsi sebelum Python 3.3
        # (aman dari timing attacks)
        return hashlib.pbkdf2_hmac('sha256', h_check.digest(), stored_hash, 1) == hashlib.pbkdf2_hmac('sha256', stored_hash, stored_hash, 1)
    
    except (base64.binascii.Error, ValueError):
        # Handle jika string hash tidak valid
        return False

# --- REQ 2: FUNGSI VIGENERE & XOR (Kronologi) ---
# (Fungsi tidak berubah)
def vigenere_cipher(data_bytes, key_str, decrypt=False):
    key_bytes = key_str.encode('utf-8')
    key_len = len(key_bytes)
    result = bytearray()
    for i, byte in enumerate(data_bytes):
        key_byte = key_bytes[i % key_len]
        if decrypt:
            shifted = (byte - key_byte) % 256
        else:
            shifted = (byte + key_byte) % 256
        result.append(shifted)
    return bytes(result)

def xor_cipher(data_bytes, key_str):
    key_bytes = key_str.encode('utf-8')
    result = bytearray()
    for data_byte, key_byte in zip(data_bytes, itertools.cycle(key_bytes)):
        result.append(data_byte ^ key_byte)
    return bytes(result)

# --- REQ 4: FUNGSI LSB STEGANOGRAPHY (Judul -> Foto) ---
# --- PERUBAHAN: Menggunakan LSB Matching ---
def embed_message(image, message):
    """Menyisipkan pesan ke dalam gambar (Pillow Image) menggunakan LSB Matching."""
    message += "####"  # Penanda akhir
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    message_len = len(binary_message)

    # Pastikan gambar dalam mode RGB
    if image.mode != 'RGB':
        image = image.convert('RGB')
        
    image_data = np.array(image)
    flat_image = image_data.flatten()

    if message_len > len(flat_image):
        raise ValueError("Pesan terlalu panjang untuk gambar ini.")

    # --- INI ADALAH LOGIKA LSB MATCHING (+/- 1) ---
    for i in range(message_len):
        pixel_value = flat_image[i]
        message_bit = int(binary_message[i])
        
        # Bandingkan LSB piksel dengan bit pesan
        pixel_lsb = pixel_value & 1
        
        if pixel_lsb != message_bit:
            # LSB tidak cocok, perlu diubah
            if pixel_value == 0:
                # Edge case: tidak bisa dikurangi, harus ditambah
                flat_image[i] = 1
            elif pixel_value == 255:
                # Edge case: tidak bisa ditambah, harus dikurangi
                flat_image[i] = 254
            else:
                # Lakukan +/- 1 secara acak
                adjustment = random.choice([-1, 1])
                flat_image[i] = pixel_value + adjustment
        # else:
            # LSB sudah cocok, tidak perlu melakukan apa-apa

    new_image_data = flat_image.reshape(image_data.shape)
    return Image.fromarray(new_image_data.astype('uint8'))

# --- PERUBAHAN: TIDAK ADA ---
# Fungsi extract_message (LSB) tidak perlu diubah.
# Ia hanya membaca LSB, tidak peduli bagaimana LSB itu ditulis.
def extract_message(image):
    """Membaca pesan dari gambar (Pillow Image)."""
    if image.mode != 'RGB':
        image = image.convert('RGB')
        
    image_data = np.array(image)
    flat_image = image_data.flatten()

    binary_message = ''.join(str(byte & 1) for byte in flat_image)

    chars = []
    for i in range(0, len(binary_message), 8):
        byte_str = binary_message[i:i+8]
        if len(byte_str) == 8:
            char = chr(int(byte_str, 2))
            chars.append(char)
            # Cek penanda akhir
            if ''.join(chars).endswith("####"):
                break
        else:
            break # Data tidak lengkap

    decoded_message = ''.join(chars)
    end_marker_index = decoded_message.find("####")
    if end_marker_index != -1:
        return decoded_message[:end_marker_index]
    return None # Penanda tidak ditemukan

# --- REQ 5: FUNGSI 3DES (File Lampiran) ---
# (Fungsi tidak berubah)
def encrypt_3des(data_bytes, key_str):
    key = derive_key(key_str, 24)  # 3DES butuh 24 byte
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data_bytes, DES3.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def decrypt_3des(encrypted_data, key_str):
    key = derive_key(key_str, 24)
    iv = encrypted_data[:DES3.block_size]
    ciphertext = encrypted_data[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        return decrypted_data
    except (ValueError, KeyError):
        st.error("Dekripsi 3DES Gagal: Kunci salah atau data korup.")
        return None

# --- REQ 7: FUNGSI BLOWFISH (Lapisan Enkripsi Final) ---
# (Fungsi tidak berubah)
def encrypt_blowfish(data_bytes, key_str):
    key = derive_key(key_str, 32)  # Blowfish (16-448 bit), kita pakai 256bit=32byte
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data_bytes, Blowfish.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def decrypt_blowfish(encrypted_data, key_str):
    key = derive_key(key_str, 32)
    iv = encrypted_data[:Blowfish.block_size]
    ciphertext = encrypted_data[Blowfish.block_size:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
        return decrypted_data
    except (ValueError, KeyError):
        st.error("Dekripsi Blowfish Gagal: Kunci salah atau data korup.")
        return None

# --- FUNGSI LOGIN / REGISTER (Menggunakan Req 1) ---
# (Fungsi tidak berubah)
def register_user(nama, username, email, password):
    password_hashed = hash_password(password) # Req 1 (BLAKE2b)
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT * FROM user WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                return False
            cursor.execute("INSERT INTO user (nama, username, email, password) VALUES (?, ?, ?, ?)",
                           (nama, username, email, password_hashed))
            connection.commit()
            return True
        except Exception as e:
            st.error(f"Terjadi kesalahan: {e}")
        finally:
            cursor.close()
            connection.close()
    return False

def login_user(username, password):
    connection = create_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user and check_password(password, user['password']): # Req 1 (BLAKE2b)
                st.session_state.is_logged_in = True
                st.session_state.user_data = user
                return user
        except Exception as e:
            st.error(f"Terjadi kesalahan: {e}")
        finally:
            cursor.close()
            connection.close()
    return None

def login_admin(username, password):
    if username == "admin" and password == "admin":
        st.session_state.is_logged_in = True
        st.session_state.user_data = {'nama': 'Admin', 'id': 0, 'username': 'admin'}
        st.session_state.current_page = "Admin"
        return True
    return False

def logout():
    st.session_state.is_logged_in = False
    st.session_state.user_data = None
    st.session_state.current_page = "Login"

# --- FUNGSI SIMPAN PENGADUAN (Baru) ---
# (Fungsi tidak berubah)
def save_pengaduan(id_pelapor, encrypted_kronologi_b64, encrypted_foto_b64=None, encrypted_file_b64=None, original_filename=None):
    """Menyimpan data (yang sudah dienkripsi) dan nama file asli ke DB."""
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO aduan (id_pelapor, judul_pengaduan, kronologi, bukti_foto, bukti_file, nama_file_asli)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (id_pelapor, None, encrypted_kronologi_b64, encrypted_foto_b64, encrypted_file_b64, original_filename)
            )
            connection.commit()
            return True
        except Exception as e:
            st.error(f"Terjadi kesalahan saat menyimpan ke database: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    return False


def dashboard_page(): # <-- DIPULIHKAN
    # Menggunakan HTML wrapper untuk menerapkan class CSS ke seluruh konten yang dimuat
    st.markdown('<div class="dashboard-content-card">', unsafe_allow_html=True) 
    
    # 1. HEADER
    st.markdown(
        '<div style="text-align:center; padding-top:20px;">'
        '<h1 style="font-size: 2.5rem; margin-bottom: 0.5rem; color: #4CAF50;">Selamat Datang di Sistem Pengaduan Rahasia</h1>'
        '<p style="font-size:1.1rem; margin-bottom: 2rem; color: #E0E0E0;">Aplikasi ini menggabungkan multi-algoritma kriptografi dan steganografi untuk menjamin kerahasiaan serta integritas data pengaduan Anda.</p>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("<hr style='border-top: 1px solid #777; margin: 30px 0;'>", unsafe_allow_html=True)
    
    # 2. KONTEN ALGORITMA
    st.markdown('<h2 style="text-align:center; font-weight:700; margin-top: 25px; margin-bottom: 25px; color: white;">Urutan Algoritma Enkripsi Data Pengaduan</h2>', unsafe_allow_html=True)

    # Data Teks
    st.markdown('### 🌟 Data Teks (Kronologi)')
    st.markdown("""
    <div style="padding-left: 20px; color: white;">
    <ol>
    <li>Kronologi dienkripsi menggunakan <strong>XOR Cipher</strong> (Kunci XOR)</li> 
    <li>Hasil XOR dienkripsi kembali menggunakan <strong>Vigenere Cipher</strong> (Kunci Vigenere)</li> 
    <li>Hasil akhir dienkripsi ulang menggunakan <strong>Blowfish</strong> (Kunci Blowfish)</li>
    </ol>
    </div>
    """, unsafe_allow_html=True)

    # Bukti Foto
    st.markdown('### 🖼️ Bukti Foto')
    st.markdown("""
    <div style="padding-left: 20px; color: white;">
    <ol>
    <li><strong>Judul Pengaduan</strong> disembunyikan ke dalam foto menggunakan <strong>LSB Matching Steganography</strong></li> 
    <li>Foto Stego (berisi Judul) dienkripsi menggunakan <strong>Blowfish</strong></li>
    </ol>
    </div>
    """, unsafe_allow_html=True)

    # Bukti File
    st.markdown('### 📂 Bukti File (Opsional)')
    st.markdown("""
    <div style="padding-left: 20px; color: white;">
    <ol>
    <li>File (PDF/DOCX) dienkripsi menggunakan <strong>Triple DES (3DES)</strong></li> 
    <li>Hasilnya kembali dienkripsi menggunakan <strong>Blowfish</strong></li>
    </ol>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div style='padding-top:20px; padding-bottom:10px;'>", unsafe_allow_html=True)
    if st.button("🚪 Mulai Menggunakan Aplikasi (Login)", use_container_width=True):
        navigate_to("Login")
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Tutup div wrapper CSS kustom: WAJIB DI AKHIR FUNGSI
    st.markdown('</div>', unsafe_allow_html=True)
# --- HALAMAN (PAGES) ---
# (Tidak ada perubahan di semua fungsi halaman)

def login_page():
    st.title("Login")
    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            if login_admin(username, password):
                st.success("Login sebagai Admin berhasil!")
                st.rerun()
            else:
                user = login_user(username, password)
                if user:
                    st.session_state.current_page = "Pengaduan"
                    st.rerun()
                else:
                    st.error("Username atau password salah!")
    
    if st.button("Belum punya akun? Register"):
        st.session_state.current_page = "Register"
        st.rerun()
    if st.button("Kembali ke Dashboard"):
        st.session_state.current_page = "Dashboard"
        st.rerun()

def register_page():
    st.title("Register")
    with st.form(key='register_form'):
        nama = st.text_input("Nama Lengkap")
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Register"):
            if register_user(nama, username, email, password):
                st.success("Registrasi berhasil! Silakan login.")
                st.session_state.current_page = "Login"
                st.rerun()
            else:
                st.error("Username atau email sudah digunakan.")
    
    if st.button("Sudah punya akun? Login"):
        st.session_state.current_page = "Login"
        st.rerun()

def pengaduan_page():
    st.title(f"Halaman Pengaduan - {st.session_state.user_data['nama']}")
    
    # if st.button("Logout"):
    #     logout()
    #     st.rerun()
    
    with st.form(key='pengaduan_form'):
        st.text_input("Nama Pelapor", value=st.session_state.user_data['nama'], disabled=True)
        
        # Input Data
        judul_pengaduan = st.text_input("Judul Pengaduan (Akan disisipkan ke foto)")
        kronologi = st.text_area("Kronologi Pengaduan")
        
        # Req 4: Bukti foto wajib untuk LSB
        st.warning("Upload foto wajib untuk menyisipkan judul.")
        bukti_foto = st.file_uploader("Upload Bukti Foto (Wajib, format PNG/JPG)", type=["png", "jpg", "jpeg"])
        
        bukti_file = st.file_uploader("Upload File Bukti (Opsional)", type=["pdf", "txt", "docx"])

        st.subheader("Kunci Enkripsi (Harap diingat!)")
        # Req 3 & 6: Input Kunci Manual
        vigenere_key = st.text_input("Kunci Vigenere (untuk Kronologi)", type="password")
        xor_key = st.text_input("Kunci XOR (untuk Kronologi)", type="password")
        des_key = st.text_input("Kunci 3DES (untuk File)", type="password")
        blowfish_key = st.text_input("Kunci Blowfish (Final)", type="password")

        if st.form_submit_button("Kirim Pengaduan"):
            # Validasi Input
            if not all([judul_pengaduan, kronologi, bukti_foto, vigenere_key, xor_key, blowfish_key]):
                st.error("Harap isi Judul, Kronologi, Bukti Foto, Kunci Vigenere, Kunci XOR, dan Kunci Blowfish.")
                return
            
            if bukti_file and not des_key:
                st.error("Harap isi Kunci 3DES jika Anda mengupload file.")
                return

            try:
                # --- ALUR ENKRIPSI ---
                
                # Req 2: Kronologi (Vigenere + XOR) -> Req 7 (Blowfish)
                kronologi_bytes = kronologi.encode('utf-8')
                xor_bytes = xor_cipher(kronologi_bytes, xor_key)
                vig_bytes = vigenere_cipher(xor_bytes, vigenere_key, decrypt=False)
                bf_vig_bytes = encrypt_blowfish(vig_bytes, blowfish_key)
                db_kronologi = base64.b64encode(bf_vig_bytes).decode('utf-8')

                # Req 4: Judul (LSB Matching) -> Req 7 (Blowfish)
                try:
                    img = Image.open(bukti_foto)
                except UnidentifiedImageError:
                    st.error("File foto tidak valid atau korup.")
                    return
                    
                stego_img = embed_message(img, judul_pengaduan)
                
                # Simpan gambar stego ke bytes (WAJIB PNG agar LSB tidak hilang)
                stego_img_bytes_io = io.BytesIO()
                stego_img.save(stego_img_bytes_io, format='PNG')
                stego_bytes = stego_img_bytes_io.getvalue()
                
                bf_stego_bytes = encrypt_blowfish(stego_bytes, blowfish_key)
                db_image = base64.b64encode(bf_stego_bytes).decode('utf-8')

                # Req 5: File (3DES) -> Req 7 (Blowfish)
                db_file = None
                
                # Inisialisasi variabel 'original_file_name' sebagai None
                original_file_name = None 
                
                if bukti_file:
                    # Tetapkan nama file JIKA file diupload
                    original_file_name = bukti_file.name 
                    file_data = bukti_file.read()
                    des_bytes = encrypt_3des(file_data, des_key)
                    bf_des_bytes = encrypt_blowfish(des_bytes, blowfish_key)
                    db_file = base64.b64encode(bf_des_bytes).decode('utf-8')
                
                # Simpan ke DB (Sekarang 'original_file_name' sudah pasti terdefinisi)
                if save_pengaduan(st.session_state.user_data['id'], db_kronologi, db_image, db_file, original_file_name):
                    st.success("Pengaduan berhasil dikirim dengan enkripsi berlapis!")
                else:
                    st.error("Pengaduan gagal dikirim.")

            except ValueError as ve:
                st.error(f"Error: {ve}") # Misal: Pesan terlalu panjang
            except Exception as e:
                st.error(f"Terjadi kesalahan enkripsi: {e}")
     

    col1, col2, col3 = st.columns([2, 6, 2])
    with col1:
        if st.button("Logout", use_container_width=True):
            logout()
            st.rerun()
def admin_page():
    st.title("Dashboard Admin")
    

    # --- Inisialisasi session state di awal ---
    if 'decrypted_files' not in st.session_state:
        st.session_state.decrypted_files = {}

    connection = create_connection()
    if not connection:
        return

    # Tabel User (Query ini sekarang BENAR, mengambil dari tabel 'user')
    st.subheader("Tabel User")
    try:
        cursor = connection.cursor(dictionary=True)
        # Query ini diperbaiki untuk mengambil data user, BUKAN aduan
        cursor.execute("SELECT id, nama, username, email FROM user")
        users = cursor.fetchall()
        st.dataframe(users)
        cursor.close()
    except Exception as e:
        st.error(f"Error saat mengambil data user: {e}")

    # Daftar Aduan (Dengan perubahan logika)
    st.subheader("Daftar Aduan")
    try:
        cursor = connection.cursor()
        
        # Query ini sekarang BENAR, mengambil 7 KOLOM
        # 'a.nama_file_asli' telah ditambahkan
        cursor.execute("""
            SELECT a.id_laporan, a.id_pelapor, a.kronologi, 
                   a.bukti_foto, a.bukti_file, a.nama_file_asli, u.nama as nama_pelapor
            FROM aduan a 
            LEFT JOIN user u ON a.id_pelapor = u.id
            ORDER BY a.id_laporan DESC
        """)
        results = cursor.fetchall()

        if results:
            for row in results:
                # Baris ini sekarang BENAR, mengharapkan 7 nilai
                (id_laporan, id_pelapor, db_kronologi, db_foto, db_file, nama_file_asli, nama_pelapor) = row
                
                with st.expander(f"Laporan #{id_laporan} - {nama_pelapor} (Perlu Kunci untuk Buka)"):
                    
                    st.warning("Data terenkripsi. Masukkan kunci yang sesuai untuk laporan ini.")
                    
                    with st.form(key=f"decrypt_form_{id_laporan}"):
                        blowfish_key = st.text_input("Kunci Blowfish", type="password", key=f"bf_{id_laporan}")
                        vigenere_key = st.text_input("Kunci Vigenere", type="password", key=f"v_{id_laporan}")
                        xor_key = st.text_input("Kunci XOR", type="password", key=f"x_{id_laporan}")
                        des_key = st.text_input("Kunci 3DES (jika ada file)", type="password", key=f"d_{id_laporan}")
                        
                        if st.form_submit_button("Dekripsi Laporan"):
                            # Bersihkan state file lama saat dekripsi baru
                            if id_laporan in st.session_state.decrypted_files:
                                del st.session_state.decrypted_files[id_laporan]

                            try:
                                # 1. Dekripsi Kronologi
                                bf_vig_bytes = base64.b64decode(db_kronologi)
                                vig_bytes = decrypt_blowfish(bf_vig_bytes, blowfish_key)
                                xor_bytes = vigenere_cipher(vig_bytes, vigenere_key, decrypt=True)
                                kronologi_bytes = xor_cipher(xor_bytes, xor_key)
                                
                                if vig_bytes is None or kronologi_bytes is None:
                                    st.error("Gagal mendekripsi kronologi (Kunci Blowfish/Vigenere/XOR salah).")
                                    continue
                                
                                decrypted_kronologi = kronologi_bytes.decode('utf-8')
                                
                                # 2. Dekripsi Foto & Ekstrak Judul
                                bf_stego_bytes = base64.b64decode(db_foto)
                                stego_bytes = decrypt_blowfish(bf_stego_bytes, blowfish_key)
                                
                                if stego_bytes is None:
                                    st.error("Gagal mendekripsi foto (Kunci Blowfish salah).")
                                    continue
                                
                                stego_img = Image.open(io.BytesIO(stego_bytes))
                                decrypted_judul = extract_message(stego_img)
                                
                                if decrypted_judul is None:
                                    st.warning("Gagal mengekstrak judul dari LSB (data korup).")
                                    decrypted_judul = "[JUDUL GAGAL DIEKSTRAK]"

                                # Tampilkan Hasil (Non-File)
                                st.subheader(f"Judul: {decrypted_judul}")
                                st.write("**Kronologi:**")
                                st.write(decrypted_kronologi)
                                st.image(stego_img, caption="Bukti Foto (sudah didekripsi)")
                                
                                # 3. Dekripsi File
                                if db_file:
                                    if not des_key:
                                        st.error("Laporan ini punya file, tapi Kunci 3DES tidak dimasukkan.")
                                    else:
                                        bf_des_bytes = base64.b64decode(db_file)
                                        des_bytes = decrypt_blowfish(bf_des_bytes, blowfish_key)
                                        
                                        if des_bytes is None:
                                            st.error("Gagal mendekripsi file (Kunci Blowfish salah).")
                                            continue
                                            
                                        file_data = decrypt_3des(des_bytes, des_key)
                                        if file_data:
                                            # Gunakan nama file asli (jika ada)
                                            final_file_name = nama_file_asli if nama_file_asli else f"laporan_{id_laporan}_file.bin"
                                            st.session_state.decrypted_files[id_laporan] = {
                                                "data": file_data,
                                                "name": final_file_name 
                                            }
                                            st.success(f"File '{final_file_name}' berhasil didekripsi. Tombol download ada di luar form.")
                                        else:
                                            st.error("Gagal mendekripsi file (Kunci 3DES salah).")
                                else:
                                    st.info("Tidak ada lampiran file pada laporan ini.")

                            except Exception as e:
                                if "can't be used in an st.form()" in str(e):
                                    st.error(f"Error Tata Letak Streamlit: {e}")
                                else:
                                    st.error(f"Error saat dekripsi: {e}. Kemungkinan besar salah satu kunci tidak cocok.")
                    
                    # Tampilkan tombol download DI LUAR form
                    if id_laporan in st.session_state.decrypted_files:
                        file_info = st.session_state.decrypted_files[id_laporan]
                        st.download_button(
                            label=f"Download File Laporan #{id_laporan} (sudah didekripsi)",
                            data=file_info['data'],
                            file_name=file_info['name'],
                            key=f"download_btn_{id_laporan}"
                        )

    except Exception as e:
        st.error(f"Terjadi kesalahan saat mengambil data aduan: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    if st.button("Logout Admin"):
        logout()
        st.rerun() # Menggunakan st.rerun

# --- Main App Router ---
def main():
    if st.session_state.current_page == "Dashboard": # <-- ADDED
        dashboard_page()
    elif st.session_state.current_page == "Login":
        login_page()
    elif st.session_state.current_page == "Register":
        register_page()
    elif st.session_state.current_page == "Pengaduan" and st.session_state.is_logged_in:
        pengaduan_page()
    elif st.session_state.current_page == "Admin" and st.session_state.is_logged_in:
        admin_page()
    else:
        st.session_state.current_page = "Dashboard" # <-- CHANGED default fallback
        dashboard_page()

if __name__ == "__main__":
    main()