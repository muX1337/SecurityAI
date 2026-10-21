FROM python:3.12-slim
WORKDIR /app
RUN pip install flask httpx --no-cache-dir
COPY vuln_ssrf_app.py .
ENV SSRF_SECURITY=medium
ENV PORT=9099
EXPOSE 9099
CMD ["python", "vuln_ssrf_app.py"]
