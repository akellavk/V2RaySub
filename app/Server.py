from pathlib import Path
from typing import Annotated
import uvicorn
from fastapi import FastAPI, HTTPException, Path as PathApi
from fastapi.responses import PlainTextResponse
import requests
import base64
import json
import os
from urllib.parse import parse_qs, unquote, urlencode
import logging
import aiosqlite

# Создаем приложение с отключенной документацией
app = FastAPI(
    title="Subscription Proxy",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# Подключение к базе данных
DB_DIR = Path("/app/db")
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "x-ui.db"
async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        yield db

# Настройка логирования
LOG_PATH = "/app/log/FastAPI-Sub.log"
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logger = logging.getLogger("FAS")
logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler()
        ]
    )

BASE_SUB_URL = os.getenv("BASE_SUB_URL", "https://127.0.0.1")
BASE_SUB_PORT = os.getenv("BASE_SUB_PORT", "2096")
SUFFIX_SUB_URL = os.getenv("SUFFIX_SUB_URL", "sub")
FULL_SUBSCRIPTION_URL = f"{BASE_SUB_URL}:{BASE_SUB_PORT}/{SUFFIX_SUB_URL}"

GITHUB_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"
LOCAL_WHITELIST_FILE = "whitelist"

def load_sni_from_github():
    """
    Загружает список SNI с GitHub
    """
    try:
        logger.info(f"Loading SNI from GitHub: {GITHUB_WHITELIST_URL}")
        response = requests.get(GITHUB_WHITELIST_URL, timeout=10)
        response.raise_for_status()
        
        sni_list = []
        for line in response.text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):  # Пропускаем пустые строки и комментарии
                sni_list.append(line)
        
        if not sni_list:
            raise ValueError("GitHub whitelist is empty")
        
        logger.info(f"Loaded {len(sni_list)} SNI domains from GitHub")
        return sni_list
        
    except Exception as e:
        logger.info(f"Error loading from GitHub: {e}")
        # Пробуем загрузить из локального файла как fallback
        return load_sni_from_local()

def load_sni_from_local():
    """
    Загружает список SNI из локального файла (fallback)
    """
    try:
        if not os.path.exists(LOCAL_WHITELIST_FILE):
            raise FileNotFoundError(f"Local whitelist file '{LOCAL_WHITELIST_FILE}' not found")
        
        with open(LOCAL_WHITELIST_FILE, 'r', encoding='utf-8') as f:
            sni_list = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    sni_list.append(line)
            
            if not sni_list:
                raise ValueError("Local whitelist file is empty")
            
            logger.info(f"Loaded {len(sni_list)} SNI domains from local file")
            return sni_list
            
    except Exception as e:
        logger.info(f"Error loading local whitelist: {e}")
        raise

async def load_sni_from_db(id_sub: str):
    """
    Загружает список SNI из базы данных
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("SELECT stream_settings FROM inbounds WHERE settings LIKE ?", (f"%{id_sub}%",))
            rows = await cursor.fetchone()
            logger.info(f"Loaded {rows} Settings domains from DB")
            if not rows:
                logger.error("No settings found in database for the given criteria")
                raise ValueError("No settings found in database")

            reality_settings = json.loads(rows[0])
            logger.info("Loaded Settings from database: %s", reality_settings)
            # Получаем serverNames
            sni_list = reality_settings.get('realitySettings', {}).get('serverNames', [])

        logger.info("Loaded SNI from database: %s", sni_list)
        if not sni_list:
            raise ValueError("Database whitelist is empty")

        logger.info(f"Loaded {len(sni_list)} SNI domains from database")
        return sni_list

    except Exception as e:
        logger.info(f"Error loading SNI from database: {e}")
        raise

def parse_vless_url(vless_url):
    """
    Парсит vless:// ссылку и возвращает конфиг в JSON формате
    """
    try:
        # Убираем префикс vless://
        if vless_url.startswith('vless://'):
            url_content = vless_url[8:]
        else:
            url_content = vless_url

        # Разделяем часть до @ и после
        if '@' in url_content:
            uuid_part, server_part = url_content.split('@', 1)
        else:
            raise ValueError("Invalid vless URL format")

        # Разделяем серверную часть на хост:порт и параметры
        if '?' in server_part:
            server_info, params_part = server_part.split('?', 1)
        else:
            server_info, params_part = server_part, ""

        # Разбираем хост и порт
        if ':' in server_info:
            host, port = server_info.rsplit(':', 1)
        else:
            raise ValueError("Invalid server format")

        # Парсим параметры
        params = parse_qs(params_part)

        # Извлекаем комментарий (после #)
        if '#' in params_part:
            params_part, comment = params_part.split('#', 1)
            comment = unquote(comment)
        else:
            comment = ""

        # Создаем JSON конфиг
        config = {
            "v": "2",
            "ps": comment or "base-config",
            "add": host,
            "port": port,
            "id": uuid_part,
            "aid": "0",
            "scy": "auto",
            "net": params.get('type', ['tcp'])[0],
            "type": "none",
            "host": "",
            "path": params.get('path', [''])[0],
            "tls": params.get('security', ['tls'])[0],
            "sni": params.get('sni', [''])[0],
            "alpn": "",
            "fp": params.get('fp', ['chrome'])[0],
            "pbk": params.get('pbk', [''])[0],
            "sid": params.get('sid', [''])[0]
        }

        # Обрабатываем flow
        if 'flow' in params:
            config['flow'] = params['flow'][0]

        # Обрабатываем encryption
        if 'encryption' in params:
            config['encryption'] = params['encryption'][0]

        print(f"Parsed vless config for: {host}:{port}")
        return config

    except Exception as e:
        print(f"Error parsing vless URL: {e}")
        return None


def json_to_vless_url(config):
    """
    Конвертирует JSON конфиг обратно в vless:// ссылку
    """
    try:
        # Базовые параметры
        uuid = config.get('id', '')
        host = config.get('add', '')
        port = config.get('port', '')
        comment = config.get('ps', '')

        # Параметры запроса
        params = {
            'type': config.get('net', 'tcp'),
            'encryption': config.get('encryption', 'none'),
            'security': config.get('tls', 'tls'),
            'fp': config.get('fp', 'chrome')
        }

        # Добавляем опциональные параметры
        if config.get('sni'):
            params['sni'] = config['sni']
        if config.get('pbk'):
            params['pbk'] = config['pbk']
        if config.get('sid'):
            params['sid'] = config['sid']
        if config.get('flow'):
            params['flow'] = config['flow']
        if config.get('path'):
            params['path'] = config['path']

        # Собираем URL
        query_string = urlencode(params, doseq=True)
        vless_url = f"vless://{uuid}@{host}:{port}?{query_string}"

        # Добавляем комментарий
        if comment:
            vless_url += f"#{comment}"

        return vless_url

    except Exception as e:
        print(f"Error converting JSON to vless URL: {e}")
        return None


def get_base_configs(sub_id: str):
    """
    Получает базовые конфиги из оригинальной подписки
    """
    try:
        print(f"Fetching base subscription from: {FULL_SUBSCRIPTION_URL}/{sub_id}")
        response = requests.get(f"{FULL_SUBSCRIPTION_URL}/{sub_id}", timeout=10)
        response.raise_for_status()

        original_content = response.text.strip()
        print(f"Raw subscription response length: {len(original_content)}")

        # Декодируем base64
        try:
            decoded_content = base64.b64decode(original_content).decode('utf-8')
            print(f"Decoded subscription: {decoded_content[:100]}...")  # Логируем начало

            configs = [line.strip() for line in decoded_content.split('\n') if line.strip()]
            print(f"Found {len(configs)} config lines in subscription")

            # Парсим каждую конфигурацию
            valid_configs = []
            for config_line in configs:
                # Если это vless:// ссылка
                if config_line.startswith('vless://'):
                    config = parse_vless_url(config_line)
                    if config:
                        valid_configs.append(config)
                        print(f"Successfully parsed vless config")
                # Если это JSON
                else:
                    try:
                        config = json.loads(config_line)
                        valid_configs.append(config)
                        print(f"Valid JSON config: {config.get('ps', 'Unknown')}")
                    except json.JSONDecodeError:
                        print(f"Invalid JSON, trying as vless URL: {config_line[:50]}...")
                        # Пробуем распарсить как vless
                        config = parse_vless_url(config_line)
                        if config:
                            valid_configs.append(config)

            return valid_configs

        except Exception as e:
            print(f"Error decoding base64 subscription: {e}")
            return []

    except requests.RequestException as e:
        print(f"Error fetching base subscription: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error in get_base_configs: {e}")
        return []


@app.get("/sub/{id_sub}", response_class=PlainTextResponse)
async def multi_subscription(id_sub: Annotated[str, PathApi(..., title="Здесь указывается Subscribe ID из x-ui")]):
    """
    Генерирует подписку с несколькими SNI на основе базовой подписки
    """
    try:
        # Загружаем SNI с GitHub
        # sni_list = load_sni_from_github()
        sni_list = await load_sni_from_db(id_sub)
        print(f"Processing {len(sni_list)} SNI domains")

        # Получаем базовые конфиги
        base_configs = get_base_configs(id_sub)
        print(f"Processing {len(base_configs)} base configs")

        if not base_configs:
            return "Error: No valid configurations found in base subscription"

        multi_configs = []

        # Создаем конфиг для каждого SNI и каждого базового конфига
        for base_config in base_configs:
            for sni in sni_list:
                new_config = base_config.copy()
                new_config['sni'] = sni

                # Обновляем описание
                original_ps = base_config.get('ps', 'base-config')
                new_config['ps'] = f"{original_ps} - sni:{sni}"

                # Конвертируем обратно в vless URL
                vless_url = json_to_vless_url(new_config)
                if vless_url:
                    multi_configs.append(vless_url)

        print(f"Generated {len(multi_configs)} total configs")

        if not multi_configs:
            return "Error: No configurations generated"

        # Кодируем обратно в base64
        combined_configs = '\n'.join(multi_configs)
        encoded_output = base64.b64encode(combined_configs.encode('utf-8')).decode('utf-8')

        print(f"Successfully generated subscription with {len(multi_configs)} configs")
        return encoded_output

    except Exception as e:
        error_msg = f"Error processing subscription: {str(e)}"
        print(error_msg)
        return error_msg

@app.get("/debug-sni-list")
async def debug_sni_list():
    """
    Отладочный эндпоинт для проверки SNI списка
    """
    try:
        sni_list = load_sni_from_github()
        return {
            "status": "success",
            "sni_count": len(sni_list),
            "sni_list": sni_list[:10]  # Показываем первые 10 SNI
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reload-whitelist")
async def reload_whitelist():
    """
    Перезагружает whitelist (для проверки без перезапуска сервера)
    """
    try:
        sni_list = load_sni_from_github()
        return {
            "status": "success",
            "message": f"Whitelist reloaded successfully",
            "domains_loaded": len(sni_list),
            "source": "github"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("Server:app", host="0.0.0.0", port=9898, reload=True)