#!/bin/bash
# Script de prueba (punto 2.e): agrega fecha y hora al final del archivo cada 10 s
while true; do
  echo "Ejecutado el $(date '+%Y-%m-%d %H:%M:%S')" >> /var/log/registro-fecha.log
  sleep 10
done
