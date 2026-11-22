FROM apache/airflow:3.1.1
USER airflow
RUN pip install "pandas>=1.3.5" && \
    pip install --no-deps "sqlalchemy-redshift>=0.8.11"
