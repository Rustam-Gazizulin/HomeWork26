FROM python3.10

WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY run.py .
COPY project .
ENV FLASK_APP=run.py


CMD flask run -h 0.0.0.0 -p 80