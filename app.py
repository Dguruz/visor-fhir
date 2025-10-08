
import requests
import streamlit as st
from streamlit.components.v1 import html

# ---------------- Config ----------------
st.set_page_config(page_title="One-Click Visor", layout="centered")

# Constantes internas (no visibles en UI)
DEFAULT_TARGET_URL = "https://34.36.14.133.nip.io/"
DEFAULT_TOKEN_ENDPOINT = "https://34.120.9.69.nip.io/api-ux-visor-fhir/v1/auth/token"
DEFAULT_BASE_KEY = "a1c071df1e1b2f4d295d6a44d24ce9e1"
VERIFY_SSL = True  # Cambia a False solo si hay problemas de certificado y sabes lo que haces
LOAD_FIRST_TIME_API = True
# ---------------- Helpers ----------------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def encrypt_text_aes256_cbc(plaintext: str, base_key: str) -> str:
    """
    Equivalente a la función Node.js:
      - AES-256-CBC
      - Clave: string UTF-8 (32 bytes)
      - IV aleatorio de 16 bytes
      - PKCS#7
      - Salida: "ivHex:cipherHex"
    """
    try:
        from Crypto.Cipher import AES  # pycryptodome
        from Crypto.Random import get_random_bytes
    except Exception as e:
        raise RuntimeError("Falta 'pycryptodome'. Instala con: pip install pycryptodome") from e

    key = base_key.encode("utf-8")
    if len(key) != 32:
        raise ValueError("La clave AES-256 debe tener 32 bytes.")

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pkcs7_pad(plaintext.encode("utf-8"), 16)
    encrypted = cipher.encrypt(padded)

    return f"{iv.hex()}:{encrypted.hex()}"

def get_temp_token(patient_identifier: str):
    global LOAD_FIRST_TIME_API
    
    headers = {"Content-Type": "application/json"}  # ← Mover aquí primero
    
    if LOAD_FIRST_TIME_API:
        requests.post(DEFAULT_TOKEN_ENDPOINT, headers=headers, json={}, timeout=20, verify=VERIFY_SSL)
        LOAD_FIRST_TIME_API = False
    
    body = {
        "patientIdentifier": patient_identifier,
        "practitionerIdentifier": "a578f7e0fc41136e6599d65f9c7fa6c1:2d0dcd874600aac407238cf48ac4b57e",
        "specialtyCode": "a578f7e0fc41136e6599d65f9c7fa6c1:e05b696dbbd456bcd73d77944e8415d7",
        "user": "a578f7e0fc41136e6599d65f9c7fa6c1:92b87c35d39f88420d87a7ed623fffde924e1e65b8c06241a8c2bea192591fb3",
        "password": "cc018822e0d68fca5bf9081f7965f44f:f4d88ab12e12d2e390f5f4cbf28466cc3da7a465c75f16e7f4dcee668416a991",
    }
    resp = requests.post(DEFAULT_TOKEN_ENDPOINT, headers=headers, json=body, timeout=20, verify=VERIFY_SSL)
    resp.raise_for_status()
    data = resp.json()
    if "temp_token" not in data:
        raise ValueError("La respuesta no contiene 'temp_token'.")
    return data["temp_token"]

def open_new_tab(url: str):
    # Abre automáticamente en nueva pestaña/ventana
    html(f"<script>window.open('{url}', '_blank');</script>", height=0)

# ---------------- UI ----------------
st.title("Visor FHIR 🔭")
plaintext = st.text_input("Ingrese el número de documento del paciente (DNI)", value="46927891")
if st.button("Abrir visor ahora"):
    try:
        encrypted_value = encrypt_text_aes256_cbc(plaintext, DEFAULT_BASE_KEY)
        temp_token = get_temp_token(encrypted_value)
        final_url = f"{DEFAULT_TARGET_URL}?temp_token={temp_token}"
        # Redirección automática (nueva pestaña)
        open_new_tab(final_url)
        st.success("Listo. Se abrió el visor en una nueva pestaña")
    except requests.HTTPError as e:
        try:
            st.error(f"HTTP {e.response.status_code}: {e.response.text}")
        except:
            st.error(f"HTTP error: {e}")
    except Exception as e:
        st.error(f"Error: {e}")


st.caption("Consideraciones 👀")
st.caption("- Si el navegador bloquea la apertura automática de ventanas, habilitar los pop-ups para este sitio")
st.caption("- La primera carga puede demorar hasta 30 segundos, luego será más rápido")

