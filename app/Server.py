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
app = FastAPI(title="Subscription Proxy", docs_url=None, redoc_url=None, openapi_url=None)

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
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()])

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
        logger.info(f"=== Parsing vless URL ===")
        logger.info(f"Original URL: {vless_url}")

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

        # Разделяем серверную часть на параметры и комментарий
        if '#' in server_part:
            # Разделяем на часть с параметрами и комментарий
            params_part, comment = server_part.split('#', 1)
            comment = unquote(comment)
        else:
            params_part, comment = server_part, ""

        # Теперь разделяем серверную часть на хост:порт и параметры
        if '?' in params_part:
            server_info, query_part = params_part.split('?', 1)
        else:
            server_info, query_part = params_part, ""

        # Разбираем хост и порт
        if ':' in server_info:
            host, port = server_info.rsplit(':', 1)
        else:
            raise ValueError("Invalid server format")

        # Парсим параметры запроса
        params = parse_qs(query_part)

        # Детально логируем все параметры
        logger.info(f"All parameters found in URL:")
        for key, values in params.items():
            logger.info(f"  {key}: {values}")

        # Создаем JSON конфиг
        config = {"v": "2", "ps": comment or "base-config", "add": host, "port": port, "id": uuid_part, "aid": "0",
            "scy": "auto", "net": params.get('type', ['tcp'])[0], "type": "none", "host": "",
            "path": params.get('path', [''])[0], "tls": params.get('security', ['tls'])[0],
            "sni": params.get('sni', [''])[0], "alpn": "", "fp": params.get('fp', ['chrome'])[0],
            "pbk": params.get('pbk', [''])[0], "sid": params.get('sid', [''])[0], "spx": params.get('spx', [''])[0]}

        # Обрабатываем flow
        if 'flow' in params:
            config['flow'] = params['flow'][0]

        # Обрабатываем encryption
        if 'encryption' in params:
            config['encryption'] = params['encryption'][0]

        # Обрабатываем allowInsecure для WebSocket
        if 'allowInsecure' in params:
            config['allowInsecure'] = params['allowInsecure'][0]

        # Обрабатываем host для WebSocket
        if 'host' in params:
            config['host'] = params['host'][0]

        logger.info(f"Config type detection:")
        logger.info(f"  Network type (net): {config['net']}")
        logger.info(f"  Security (tls): {config['tls']}")
        logger.info(f"  Has flow: {'flow' in config}")
        logger.info(f"  Has pbk: {bool(config.get('pbk'))}")

        # Определяем тип конфига
        if config['net'] == 'ws' and config['tls'] == 'tls':
            config['_config_type'] = 'websocket'
            logger.info(f"  Detected: WebSocket config")
        elif config['tls'] == 'reality' and config.get('pbk'):
            config['_config_type'] = 'reality'
            logger.info(f"  Detected: Reality config")
        else:
            config['_config_type'] = 'other'
            logger.info(f"  Detected: Other config type")

        logger.info(f"Final config keys: {list(config.keys())}")
        logger.info(f"Comment (ps): '{comment}'")
        logger.info(f"=== End parsing ===\n")

        return config

    except Exception as e:
        logger.info(f"Error parsing vless URL: {e}")
        import traceback
        logger.info(traceback.format_exc())
        return None


def json_to_vless_url(config):
    """
    Конвертирует JSON конфиг обратно в vless:// ссылку
    """
    try:
        logger.info(f"=== Converting JSON to vless URL ===")
        logger.info(f"Config type: {config.get('_config_type', 'unknown')}")
        logger.info(f"Config keys: {list(config.keys())}")

        # Базовые параметры
        uuid = config.get('id', '')
        host = config.get('add', '')
        port = config.get('port', '')
        comment = config.get('ps', '')

        # Обязательные параметры
        params = {'type': config.get('net', 'tcp'), 'encryption': config.get('encryption', 'none'),
            'security': config.get('tls', 'tls')}

        # Добавляем fp только для Reality конфигов
        if config.get('_config_type') == 'reality':
            params['fp'] = config.get('fp', 'chrome')

        # Дополнительные параметры
        optional_params = ['sni', 'pbk', 'sid', 'flow', 'path', 'spx', 'host', 'allowInsecure']
        for param in optional_params:
            value = config.get(param)
            if value:
                params[param] = value
                logger.info(f"Added {param}: {value}")

        logger.info(f"Final parameters: {params}")

        # Собираем URL
        query_string = urlencode(params, doseq=True)
        vless_url = f"vless://{uuid}@{host}:{port}?{query_string}"

        # Добавляем комментарий
        if comment:
            vless_url += f"#{comment}"

        logger.info(f"Generated URL: {vless_url}")
        logger.info(f"=== End conversion ===\n")

        return vless_url

    except Exception as e:
        logger.info(f"Error converting JSON to vless URL: {e}")
        import traceback
        logger.info(traceback.format_exc())
        return None


def get_base_configs(sub_id: str):
    """
    Получает базовые конфиги из оригинальной подписки
    """
    try:
        logger.info(f"Fetching base subscription from: {FULL_SUBSCRIPTION_URL}/{sub_id}")
        response = requests.get(f"{FULL_SUBSCRIPTION_URL}/{sub_id}", timeout=10)
        response.raise_for_status()

        original_content = response.text.strip()
        logger.info(f"Raw subscription response length: {len(original_content)}")

        # Декодируем base64
        try:
            decoded_content = base64.b64decode(original_content).decode('utf-8')
            logger.info(f"Decoded subscription: {decoded_content}")

            configs = [line.strip() for line in decoded_content.split('\n') if line.strip()]
            logger.info(f"Found {len(configs)} config lines in subscription")

            # Парсим каждую конфигурацию
            valid_configs = []
            for config_line in configs:
                # Если это vless:// ссылка
                if config_line.startswith('vless://'):
                    config = parse_vless_url(config_line)
                    if config:
                        valid_configs.append(config)
                        logger.info(f"Successfully parsed vless config: {config.get('_config_type')}")
                # Если это JSON
                else:
                    try:
                        config = json.loads(config_line)
                        valid_configs.append(config)
                        logger.info(f"Valid JSON config: {config.get('ps', 'Unknown')}")
                    except json.JSONDecodeError:
                        logger.info(f"Invalid JSON, trying as vless URL: {config_line[:50]}...")
                        # Пробуем распарсить как vless
                        config = parse_vless_url(config_line)
                        if config:
                            valid_configs.append(config)

            return valid_configs

        except Exception as e:
            logger.info(f"Error decoding base64 subscription: {e}")
            return []

    except requests.RequestException as e:
        logger.info(f"Error fetching base subscription: {e}")
        return []
    except Exception as e:
        logger.info(f"Unexpected error in get_base_configs: {e}")
        return []


def generate_multi_configs(base_configs, sni_list):
    """
    Генерирует множественные конфиги для разных SNI
    """
    multi_configs = []

    for base_config in base_configs:
        config_type = base_config.get('_config_type', 'unknown')
        logger.info(f"Processing config type: {config_type}")

        if config_type == 'reality':
            # Для Reality: создаем конфиг для каждого SNI
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

        elif config_type == 'websocket':
            # Для WebSocket: создаем конфиг для каждого SNI
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

        else:
            # Для других типов конфигов просто добавляем как есть
            vless_url = json_to_vless_url(base_config)
            if vless_url:
                multi_configs.append(vless_url)

    return multi_configs


@app.get("/sub/{id_sub}", response_class=PlainTextResponse)
async def multi_subscription(id_sub: Annotated[str, PathApi(..., title="Здесь указывается Subscribe ID из x-ui")]):
    """
    Генерирует подписку с несколькими SNI на основе базовой подписки
    """
    try:
        # Загружаем SNI с GitHub или из базы данных
        # sni_list = load_sni_from_github()
        sni_list = await load_sni_from_db(id_sub)
        logger.info(f"Processing {len(sni_list)} SNI domains")

        # Получаем базовые конфиги
        base_configs = get_base_configs(id_sub)
        logger.info(f"Processing {len(base_configs)} base configs")

        if not base_configs:
            return "Error: No valid configurations found in base subscription"

        # Генерируем множественные конфиги
        multi_configs = generate_multi_configs(base_configs, sni_list)
        logger.info(f"Generated {len(multi_configs)} total configs")

        if not multi_configs:
            return "Error: No configurations generated"

        # Кодируем обратно в base64
        combined_configs = '\n'.join(multi_configs)
        encoded_output = base64.b64encode(combined_configs.encode('utf-8')).decode('utf-8')

        logger.info(f"Successfully generated subscription with {len(multi_configs)} configs")
        return encoded_output

    except Exception as e:
        error_msg = f"Error processing subscription: {str(e)}"
        logger.info(error_msg)
        return error_msg


@app.get("/debug-sni-list")
async def debug_sni_list():
    """
    Отладочный эндпоинт для проверки SNI списка
    """
    try:
        sni_list = load_sni_from_github()
        return {"status": "success", "sni_count": len(sni_list), "sni_list": sni_list[:10]  # Показываем первые 10 SNI
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
        return {"status": "success", "message": f"Whitelist reloaded successfully", "domains_loaded": len(sni_list),
            "source": "github"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("Server:app", host="0.0.0.0", port=8000, reload=True)