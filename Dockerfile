FROM python3.9
WORKDIR /opt
ADD . .
RUN pip install -r requirements.txt
CMD ["python3", "main.py"]