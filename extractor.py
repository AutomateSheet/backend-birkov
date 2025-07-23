import imaplib
import email
from email.header import decode_header
import re
import sys
import signal
import base64
import time
import logging
from urllib.parse import quote, unquote

# Configuration du logging
logging.basicConfig(
    filename='extraction_emails.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def signal_handler(sig, frame):
    print("\n🛑 Extraction stoppée (signal reçu).", file=sys.stderr)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class TimeoutError(Exception): pass

def timeout_handler(signum, frame):
    raise TimeoutError()

signal.signal(signal.SIGALRM, timeout_handler)

def decode_mime_words(s):
    if not s:
        return ''
    decoded = decode_header(s)
    result = []
    for part, enc in decoded:
        if isinstance(part, bytes):
            try:
                if enc:
                    result.append(part.decode(enc, errors='ignore'))
                else:
                    result.append(part.decode('utf-8', errors='ignore'))
            except LookupError:
                result.append(part.decode('utf-8', errors='ignore'))
        else:
            result.append(part)
    return ''.join(result)

def extract_emails_from_text(text):
    if not text:
        return []
    raw_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    return [e for e in raw_emails if is_valid_email(e)]

def is_valid_email(email_str):
    blacklist_keywords = [
        'noreply', 'no-reply', 'nepasrepondre', 'ne-pas-repondre',
        'donotreply', 'do-not-reply', 'mailer-daemon', 'bounce',
        'postmaster', 'automated', 'robot', 'bot', 'system', 'reply',
        'newsletter', 'unsubscribe', 'mailer@', 'bounce@',
        'example@', '@domain', 'spam', 'tempmail', 'mailinblack', 'mailclient',
        'netflix', 'amazon', 'aliexpress', 'alibaba', 'zalando',
        'facebookmail', '@edf', 'mailchimp', 'leboncoin', '-news', 'news-', 'facebook',
        'pole-emploi.fr', 'bnpparibas', '@dhl', 'ionos', '@ovh', 'abuse', 'paypal',
        'microsoft','@booking.com','@dgfip.finances.gouv.fr', '@1and1.fr','ovh.net',
        'boursorama.fr','credit-agricole-sa.fr', 'caisse-epargne', 'ebay', 'banquepopulaire', 'caisse.epargne', 'mail.gmail'
    ]

    lower_email = email_str.lower()
    if any(keyword in lower_email for keyword in blacklist_keywords):
        return False
    if len(email_str) > 50:
        return False
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,}$', email_str):
        return False
    try:
        local, domain = email_str.split('@', 1)
    except ValueError:
        return False
    if sum(c.isdigit() for c in local) > 6 or sum(c.isdigit() for c in email_str) > 6:
        return False
    if local.isdigit():
        return False
    if domain.split('.')[0].isdigit():
        return False
    if re.fullmatch(r'(.)\1{5,}', local):
        return False
    return True

def decode_imap_utf7(s):
    """Décode une chaîne encodée en IMAP UTF-7 modifié"""
    if isinstance(s, bytes):
        s = s.decode('ascii', errors='ignore')

    def base64_part(m):
        b64 = m.group(1).replace(',', '/')
        missing_padding = len(b64) % 4
        if missing_padding:
            b64 += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(b64).decode('utf-16-be')
        except:
            return m.group(0)

    s = s.replace('&-', '&')
    return re.sub(r'&([A-Za-z0-9+/]+)-', base64_part, s)

def encode_imap_utf7(s):
    """Encode une chaîne en IMAP UTF-7 modifié"""
    def utf7_part(m):
        char = m.group(0)
        try:
            utf16 = char.encode('utf-16-be')
            b64 = base64.b64encode(utf16).decode('ascii')
            return '&' + b64.replace('/', ',').rstrip('=') + '-'
        except:
            return char

    return re.sub(r'[^\x00-\x7F]+', utf7_part, s)

def decode_imap_folder_name(raw_name):
    """Décode les noms de dossier IMAP avec gestion robuste"""
    if isinstance(raw_name, bytes):
        try:
            raw_name = raw_name.decode('utf-8')
        except UnicodeDecodeError:
            try:
                raw_name = raw_name.decode('latin1')
            except:
                raw_name = raw_name.decode('ascii', errors='ignore')

    if raw_name.startswith('"') and raw_name.endswith('"'):
        raw_name = raw_name[1:-1].replace('\\"', '"').replace('\\\\', '\\')

    decoded = decode_imap_utf7(raw_name)
    if decoded != raw_name:
        return decoded

    return raw_name.strip()

def encode_folder_name(folder_name):
    """Encode un nom de dossier pour IMAP avec gestion unifiée"""
    if isinstance(folder_name, bytes):
        folder_name = folder_name.decode('utf-8', errors='ignore')
        
     # Cas spécial pour les noms avec uniquement des espaces (comme "A TRAITER")
    if ' ' in folder_name and not any(ord(c) > 127 for c in folder_name) and '/' not in folder_name:
        # 1. Essayer avec guillemets simples
        encoded = f'"{folder_name}"'
        # 2. Essayer avec double backslash avant les guillemets
        alt_encoded = f'"\\"{folder_name}\\""'
        # 3. Essayer sans guillemets mais avec backslash
        alt_encoded2 = folder_name.replace(' ', '\\ ')
        
        return [encoded, alt_encoded, alt_encoded2]

    needs_utf7 = any(ord(c) > 127 for c in folder_name)
    needs_quotes = any(c.isspace() or c in '(){ %*"' for c in folder_name)

    if needs_utf7:
        folder_name = encode_imap_utf7(folder_name)

    if needs_quotes or needs_utf7:
        folder_name = folder_name.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{folder_name}"'

    return folder_name

def walk_mailboxes(imap):
    """Récupère la liste des dossiers avec gestion robuste"""
    try:
        status, mailboxes = imap.list()
        if status != 'OK':
            logging.error("Erreur: impossible de récupérer les dossiers.")
            return []
    except Exception as e:
        logging.error(f"Erreur IMAP list: {e}")
        return []

    folders = []
    for mbox in mailboxes:
        try:
            if isinstance(mbox, bytes):
                mbox = mbox.decode('utf-8', errors='replace')

            parts = [p for p in mbox.split('"') if p.strip()]
            if len(parts) >= 3:
                raw_name = parts[-1].strip()
            else:
                raw_name = mbox.split()[-1]

            folder_name = decode_imap_folder_name(raw_name)
            if folder_name:
                folders.append(folder_name)
        except Exception as e:
            logging.warning(f"Erreur décodage dossier: {mbox} - {e}")
            folders.append(f"UNKNOWN_FOLDER_{len(folders)}")

    return folders

def select_mailbox_with_timeout(imap, mailbox, timeout=15):
    """Sélectionne un dossier avec gestion robuste"""
    signal.alarm(timeout)
    try:
        # Tentative 1: Encodage standard
        encoded_mailbox = encode_folder_name(mailbox)
        status, data = imap.select(encoded_mailbox, readonly=True)
        
        if status != 'OK':
            # Tentative 2: Sans guillemets si pas d'espaces/accents
            if ' ' not in mailbox and not any(ord(c) > 127 for c in mailbox):
                status, data = imap.select(mailbox, readonly=True)
            
            if status != 'OK':
                # Tentative 3: Encodage URL
                alt_encoded = quote(mailbox)
                status, data = imap.select(alt_encoded, readonly=True)
        
        signal.alarm(0)
        return status, data
    except Exception as e:
        logging.error(f"Échec sélection dossier {mailbox}: {str(e)}")
        signal.alarm(0)
        return 'FAIL', None

def search_with_timeout(imap, criteria='ALL', timeout=15):
    signal.alarm(timeout)
    try:
        status, data = imap.search(None, criteria)
        signal.alarm(0)
        return status, data
    except TimeoutError:
        logging.warning(f"Timeout search mails (criteria={criteria})")
        signal.alarm(0)
        return 'FAIL', None
    except Exception as e:
        logging.warning(f"Erreur search mails (criteria={criteria}) : {e}")
        signal.alarm(0)
        return 'FAIL', None

def fetch_mail_body_with_timeout(imap, num, timeout=15):
    signal.alarm(timeout)
    try:
        status, data = imap.fetch(num, '(RFC822)')
        signal.alarm(0)
        return status, data
    except TimeoutError:
        logging.warning(f"Timeout fetch body mail #{num.decode()}")
        signal.alarm(0)
        return 'FAIL', None
    except Exception as e:
        logging.warning(f"Erreur fetch body mail #{num.decode()} : {e}")
        signal.alarm(0)
        return 'FAIL', None
    finally:
        signal.alarm(0)

def safe_logout(imap):
    """Ferme la connexion IMAP de manière sécurisée"""
    try:
        imap.close()
    except:
        pass
    try:
        imap.logout()
    except:
        pass

def main(user, password, imap_server, max_emails):
    extracted_emails = set()
    max_emails = int(max_emails)

    try:
        imap = imaplib.IMAP4_SSL(imap_server, timeout=30)
        imap.login(user, password)
    except Exception as e:
        print(f"Erreur connexion IMAP : {e}", file=sys.stderr)
        sys.exit(1)

    try:
        folders = walk_mailboxes(imap)
        total_folders = len(folders)
        print(f"Nombre de dossier(s) trouvé(s) : {total_folders}", file=sys.stderr)
        print(f"[PROGRESS_INIT] {total_folders}")
        sys.stdout.flush()

        current_folder_index = 0
        for mbox in folders:
            current_folder_index += 1
            print(f"[PROGRESS_UPDATE] {current_folder_index}", file=sys.stdout)
            sys.stdout.flush()

            if not mbox or mbox.startswith("UNKNOWN_FOLDER_"):
                continue

            print(f"\n🟡 Tentative d'accès au dossier: {mbox}", file=sys.stderr)
            
            # Essayer jusqu'à 3 fois pour les dossiers problématiques
            max_attempts = 3
            status = 'FAIL'
            for attempt in range(max_attempts):
                status, _ = select_mailbox_with_timeout(imap, mbox, timeout=15)
                if status == 'OK':
                    break
                time.sleep(1)  # Pause entre les tentatives
            
            if status != 'OK':
                print(f"❌ Impossible d'accéder au dossier après {max_attempts} tentatives: {mbox}", file=sys.stderr)
                continue

            status, data = search_with_timeout(imap, 'ALL', timeout=20)
            if status != 'OK':
                print(f"❌ Erreur lors de la recherche dans le dossier: {mbox}", file=sys.stderr)
                continue

            mail_ids = data[0].split()
            if mail_ids:
                print(f"🔍 {len(mail_ids)} mails trouvés dans {mbox}", file=sys.stderr)
            else:
                print(f"ℹ️ Aucun mail trouvé dans {mbox}", file=sys.stderr)
                continue

            for num in mail_ids:
                if max_emails != -1 and len(extracted_emails) >= max_emails:
                    print(f"\n🛑 Limite de {max_emails} emails atteinte", file=sys.stderr)
                    safe_logout(imap)
                    return

                status, body_data = fetch_mail_body_with_timeout(imap, num, timeout=20)
                if status != 'OK' or not body_data:
                    continue

                try:
                    body_bytes = b"".join([part for part in body_data[0] if isinstance(part, bytes)])
                    text = body_bytes.decode(errors='ignore')
                    for em in extract_emails_from_text(text):
                        if em not in extracted_emails:
                            print(em)
                            sys.stdout.flush()
                            extracted_emails.add(em)
                            if max_emails != -1 and len(extracted_emails) >= max_emails:
                                print(f"\n🛑 Limite de {max_emails} emails atteinte", file=sys.stderr)
                                safe_logout(imap)
                                return
                except Exception as e:
                    logging.warning(f"Erreur lecture body mail #{num.decode()} : {e}")

                time.sleep(0.1)

    except Exception as e:
        logging.error(f"Erreur fatale: {e}")
        print(f"\n❌ Erreur fatale: {e}", file=sys.stderr)
    finally:
        safe_logout(imap)

    if len(extracted_emails) == 0:
        print("\n❌ Aucun email valide trouvé.", file=sys.stderr)
    else:
        print(f"\n✅ {len(extracted_emails)} emails valides extraits.", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} user password imap [max_emails]", file=sys.stderr)
        sys.exit(1)

    user = sys.argv[1]
    password = sys.argv[2]
    imap_server = sys.argv[3]
    max_emails = sys.argv[4] if len(sys.argv) > 4 else "10"
    main(user, password, imap_server, max_emails)