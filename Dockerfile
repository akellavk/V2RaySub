FROM python:3.9-slim

WORKDIR /app

# Установка переменной окружения для часового пояса
ENV TZ=Asia/Omsk

# Установка системных зависимостей
RUN apt-get install -y tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

COPY ./app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app .

# Установка прав для app
RUN chmod -R 777 /app

# Создаем директорию для логов
RUN mkdir -p /app/log && \
    chmod -R 777 /app/log

CMD ["uvicorn", "Server:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--reload"]