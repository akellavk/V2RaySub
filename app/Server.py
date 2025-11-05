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
        return None

async def load_sni_from_db(id_sub: str):
    """
    Загружает список SNI из базы данных для разных типов конфигураций
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("SELECT stream_settings FROM inbounds WHERE settings LIKE ?", (f"%{id_sub}%",))
            rows = await cursor.fetchone()

            if not rows:
                logger.error("No settings found in database for the given criteria")
                raise ValueError("No settings found in database")

            stream_settings = json.loads(rows[0])
            logger.info("Loaded stream_settings from database")

            security_type = stream_settings.get('security', '')
            network_type = stream_settings.get('network', '')

            logger.info(f"Security type: {security_type}, Network type: {network_type}")

            sni_list = []

            # Для Reality конфигураций
            if security_type == 'reality':
                reality_settings = stream_settings.get('realitySettings', {})
                sni_list = reality_settings.get('serverNames', [])
                logger.info(f"Loaded {len(sni_list)} SNI domains from Reality settings")

            # Для TLS конфигураций (WebSocket)
            elif security_type == 'tls' and network_type == 'ws':
                tls_settings = stream_settings.get('tlsSettings', {})
                server_name = tls_settings.get('serverName', '')

                # Разделяем домены, если они указаны через запятую
                if server_name:
                    sni_list = [domain.strip() for domain in server_name.split(',') if domain.strip()]
                    logger.info(f"Loaded {len(sni_list)} SNI domains from WebSocket TLS settings: {sni_list}")
                else:
                    logger.warning("No serverName found in TLS settings for WebSocket")

            else:
                logger.warning(f"Unsupported configuration type: security={security_type}, network={network_type}")
                return []

            if not sni_list:
                raise ValueError("No SNI domains found in database for this configuration")

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

        # Создаем JSON конфиг
        config = {"v": "2", "ps": comment or "base-config", "add": host, "port": port, "id": uuid_part, "aid": "0",
            "scy": "auto", "net": params.get('type', ['tcp'])[0], "type": "none", "host": "",
            "path": params.get('path', [''])[0], "tls": params.get('security', ['tls'])[0],
            "sni": params.get('sni', [''])[0], "alpn": "", "fp": params.get('fp', ['chrome'])[0],
            "pbk": params.get('pbk', [''])[0], "sid": params.get('sid', [''])[0], "spx": params.get('spx', [''])[0]}

        # Обрабатываем дополнительные параметры
        if 'flow' in params:
            config['flow'] = params['flow'][0]
        if 'encryption' in params:
            config['encryption'] = params['encryption'][0]
        if 'allowInsecure' in params:
            config['allowInsecure'] = params['allowInsecure'][0]
        if 'host' in params:
            config['host'] = params['host'][0]

        # ОПРЕДЕЛЕНИЕ ТИПА КОНФИГА - УПРОЩЕННАЯ ЛОГИКА
        config_type = 'other'

        # WebSocket detection
        if config['net'] == 'ws':
            config_type = 'websocket'
        # Reality detection
        elif config['tls'] == 'reality' and config.get('pbk'):
            config_type = 'reality'

        config['_config_type'] = config_type

        logger.info(f"Config type: {config_type}")
        logger.info(f"Network: {config['net']}, Security: {config['tls']}")
        logger.info(f"SNI: {config['sni']}")
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

        # Собираем URL
        query_string = urlencode(params, doseq=True)
        vless_url = f"vless://{uuid}@{host}:{port}?{query_string}"

        # Добавляем комментарий
        if comment:
            vless_url += f"#{comment}"

        logger.info(f"Generated URL length: {len(vless_url)}")
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
            logger.info(f"First 200 chars of decoded: {decoded_content[:200]}")

            configs = [line.strip() for line in decoded_content.split('\n') if line.strip()]
            logger.info(f"Found {len(configs)} config lines in subscription")

            # Парсим каждую конфигурацию
            valid_configs = []
            for config_line in configs:
                if config_line.startswith('vless://'):
                    config = parse_vless_url(config_line)
                    if config:
                        valid_configs.append(config)
                        logger.info(f"Parsed config type: {config.get('_config_type')}")
                else:
                    try:
                        config = json.loads(config_line)
                        valid_configs.append(config)
                    except json.JSONDecodeError:
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
        current_sni = base_config.get('sni', '')

        logger.info(f"Processing config type: {config_type}, current SNI: {current_sni}")

        if config_type == 'reality':
            # Для Reality: создаем конфиг для каждого SNI
            for sni in sni_list:
                new_config = base_config.copy()
                new_config['sni'] = sni
                new_config['ps'] = f"{base_config.get('ps', 'base-config')} - sni:{sni}"

                vless_url = json_to_vless_url(new_config)
                if vless_url:
                    multi_configs.append(vless_url)

        elif config_type == 'websocket':
            # ДЛЯ WEBSOCKET: ВСЕГДА создаем конфиги для каждого SNI из списка
            # независимо от того, есть ли уже SNI в базовом конфиге
            logger.info(f"WebSocket config - generating configs for {len(sni_list)} SNIs")

            for sni in sni_list:
                new_config = base_config.copy()
                new_config['sni'] = sni
                new_config['ps'] = f"{base_config.get('ps', 'base-config')} - sni:{sni}"

                vless_url = json_to_vless_url(new_config)
                if vless_url:
                    multi_configs.append(vless_url)
                    logger.info(f"Added WebSocket config with SNI: {sni}")

        else:
            # Для других типов конфигов просто добавляем как есть
            vless_url = json_to_vless_url(base_config)
            if vless_url:
                multi_configs.append(vless_url)

    logger.info(f"Total generated configs: {len(multi_configs)}")
    return multi_configs


@app.get("/sub/{id_sub}", response_class=PlainTextResponse)
async def multi_subscription(id_sub: Annotated[str, PathApi(..., title="Subscribe ID")]):
    """
    Генерирует подписку с несколькими SNI на основе базовой подписки
    """
    try:
        # Загружаем SNI из базы данных
        sni_list = await load_sni_from_db(id_sub)
        logger.info(f"Loaded {len(sni_list)} SNI domains: {sni_list}")

        # Получаем базовые конфиги
        base_configs = get_base_configs(id_sub)
        logger.info(f"Found {len(base_configs)} base configs")

        if not base_configs:
            return "Error: No valid configurations found in base subscription"

        # Логируем типы конфигов для отладки
        for i, config in enumerate(base_configs):
            logger.info(
                f"Base config {i}: type={config.get('_config_type')}, net={config.get('net')}, tls={config.get('tls')}, sni={config.get('sni')}")

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

@app.get("/subf/{id_sub}", response_class=PlainTextResponse)
async def multi_subscription_all(id_sub: Annotated[str, PathApi(..., title="Subscribe ID")]):
    """
    Генерирует подписку со всеми SNI на основе базовой подписки
    """
    try:
        # Загружаем SNI из базы данных
        sni_list = load_sni_from_github()
        logger.info(f"Loaded {len(sni_list)} SNI domains: {sni_list}")

        # Получаем базовые конфиги
        base_configs = get_base_configs(id_sub)
        logger.info(f"Found {len(base_configs)} base configs")

        if not base_configs:
            return "Error: No valid configurations found in base subscription"

        # Логируем типы конфигов для отладки
        for i, config in enumerate(base_configs):
            logger.info(
                f"Base config {i}: type={config.get('_config_type')}, net={config.get('net')}, tls={config.get('tls')}, sni={config.get('sni')}")

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


@app.get("/debug-configs/{id_sub}")
async def debug_configs(id_sub: str):
    """
    Отладочный эндпоинт для проверки конфигов
    """
    try:
        sni_list = await load_sni_from_db(id_sub)
        base_configs = get_base_configs(id_sub)

        configs_info = []
        for i, config in enumerate(base_configs):
            config_info = {"index": i, "type": config.get('_config_type', 'unknown'), "ps": config.get('ps', 'unknown'),
                "net": config.get('net', 'unknown'), "tls": config.get('tls', 'unknown'),
                "sni": config.get('sni', 'not_set'), "has_pbk": bool(config.get('pbk')),
                "has_flow": bool(config.get('flow'))}
            configs_info.append(config_info)

        # Генерируем пример multi-конфигов
        multi_configs = generate_multi_configs(base_configs, sni_list[:3])  # Берем только 3 для примера

        return {"status": "success", "sni_count": len(sni_list), "sni_list": sni_list,
            "base_configs_count": len(base_configs), "base_configs": configs_info,
            "multi_configs_sample": multi_configs[:3] if multi_configs else []  # Показываем первые 3
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("Server:app", host="0.0.0.0", port=8000, reload=True)