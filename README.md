# Docker Compose образ FastAPI для генерации множественных подписок панели 3X-UI

Этот репозиторий содержит Docker Compose файл для развертывания FastAPI приложения, которое генерирует множественные подписки для панели 3X-UI.

## Требования
- Docker
- Docker Compose
- Python 3.7+
- Библиотеки Python: fastapi, uvicorn, requests, aiosqlite

## Установка и настройка
1. Клонируйте репозиторий:
   ```bash
   # Перейдите в каталог где хотите развернуть проект
   cd /srv
   # Склонируйте репозиторий
   git clone https://github.com/akellavk/V2RaySub.git
   # Перейдите в каталог проекта
   cd V2RaySub
   # Отредактируйте docker-compose.yml заменив переменные окружения на свои
   nano docker-compose.yml
   # Выполните запуск Docker Compose
   docker-compose up -d --build
    ```

## Использование
После запуска контейнера, FastAPI приложение будет доступно по адресу `https://<YOUR_SERVER_IP>:<YOUR_PORT>`. По умолчанию порт 8000.
Вы можете получить для одного конфига несколько конфигураций с различными sni, отправив GET запрос на `https://<YOUR_SERVER_IP>:<YOUR_PORT>/sub/<SUB_ID>`. 
Например: `https://<YOUR_SERVER_IP>:<YOUR_PORT>/sub/uhzb35qqnojqorbk`