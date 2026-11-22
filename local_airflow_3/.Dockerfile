FROM apache/airflow:3.1.1
USER airflow
RUN pip install "pandas>=1.3.5"
