# 

## Requirements

- Python 3.x
- Library yang dibutuhkan ada di `requirements.txt`:
  - flask==3.0.3
  - httpx==0.27.2
  - pyyaml==6.0.2

## Instalasi

1. Download project ini, pilih salah satu cara:

   **Opsi A: Clone via Git**
   ```
   git clone https://github.com/.git
   cd 
   ```

   **Opsi B: Download ZIP**
   - Buka halaman repo: https://github.com/
   - Klik tombol hijau **Code** > **Download ZIP**
   - Extract file ZIP yang sudah didownload
   - Buka terminal/cmd, arahkan ke folder hasil extract:
     ```
     cd path/ke/folder/
     ```

2. Buat virtual environment
   ```
   python -m venv venv
   ```

3. Aktifkan virtual environment

   Windows:
   ```
   venv\Scripts\activate
   ```

   Mac/Linux:
   ```
   source venv/bin/activate
   ```

4. Install dependencies
   ```
   pip install -r requirements.txt
   ```

## Menjalankan Aplikasi

```
python app.py
```

Setelah berjalan, buka browser dan akses:

```
http://127.0.0.1:5000
```

## Catatan

- Folder `venv` sengaja tidak disertakan di repository ini. Virtual environment akan otomatis terbentuk saat menjalankan langkah instalasi di atas.
- Jika menambahkan library baru, jangan lupa update `requirements.txt` dengan:
  ```
  pip freeze > requirements.txt
  ```
